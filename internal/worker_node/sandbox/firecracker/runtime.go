/*
 * MIT License
 *
 * Copyright (c) 2024 EASL
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package firecracker

import (
	"cluster_manager/api/proto"
	"cluster_manager/internal/worker_node/managers"
	"cluster_manager/internal/worker_node/sandbox"
	"cluster_manager/internal/worker_node/sandbox/containerd"
	"context"
	"fmt"
	"github.com/coreos/go-iptables/iptables"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Runtime struct {
	sandbox.RuntimeInterface

	cpApi       proto.CpiInterfaceClient
	idGenerator *managers.ThreadSafeRandomGenerator

	VMDebugMode  bool
	UseSnapshots bool

	KernelPath     string
	FileSystemPath string
	ImageRootfsDir string // benchmark-time: per-image rootfs dir (imageRootfsFor)
	NetworkManager *NetworkPoolManager

	SandboxManager  *managers.SandboxManager
	ProcessMonitor  *managers.ProcessMonitor
	SnapshotManager *SnapshotManager
	IPT             *iptables.IPTables

	forwarders     map[string]*tcpForwarder
	forwarderMutex sync.Mutex
}

type FirecrackerMetadata struct {
	managers.RuntimeMetadata

	VMCS *VMControlStructure
}

func NewFirecrackerRuntime(cpApi proto.CpiInterfaceClient, sandboxManager *managers.SandboxManager,
	kernelPath string, fileSystemPath string, imageRootfsDir string,
	internalIPPrefix string, externalIPPrefix string,
	vmDebugMode bool, useSnapshots bool, networkPoolSize int) *Runtime {

	DeleteAllSnapshots()
	err := DeleteUnusedNetworkDevices()
	if err != nil {
		logrus.Error("Failed to remove some or all network devices.")
	}

	ipt, err := managers.NewIptablesUtil()
	if err != nil {
		logrus.Fatal("Failed to start iptables utility. Terminating worker daemon.")
	}

	return &Runtime{
		cpApi:       cpApi,
		idGenerator: managers.NewThreadSafeRandomGenerator(),

		VMDebugMode:  vmDebugMode,
		UseSnapshots: useSnapshots,

		KernelPath:     kernelPath,
		FileSystemPath: fileSystemPath,
		ImageRootfsDir: imageRootfsDir,
		NetworkManager: NewNetworkPoolManager(internalIPPrefix, externalIPPrefix, networkPoolSize),

		SandboxManager:  sandboxManager,
		ProcessMonitor:  managers.NewProcessMonitor(),
		SnapshotManager: NewFirecrackerSnapshotManager(),
		IPT:             ipt,

		forwarders: make(map[string]*tcpForwarder),
	}
}

// imageRootfsFor selects the per-image rootfs source for a sandbox, based
// on the image reference in the CreateSandbox request (in.Image). Benchmark-time
// patch: Dirigent originally boots every VM from the single configured
// firecrackerFileSystem and uses in.Image only as a snapshot-cache key
// (runtime.go FindSnapshot/AddSnapshot). To let each lane boot the SWE-bench
// repo its commands were recorded against (see replay_symmetric_mismatch.py)
// instead of every VM sharing one rootfs, ImageRootfsDir is scanned for a
// rootfs file named after the image's repo:
//
//	ghcr.io/swe-images/sympy_final:5289eeb... -> <dir>/rootfs-sympy_final.ext4
//	ghcr.io/swe-images/sympy_final@sha256:abc -> <dir>/rootfs-sympy_final-abc.ext4
//
// If ImageRootfsDir is empty or no matching rootfs exists, the worker's
// default FileSystemPath is used (Dirigent's original behavior), so the
// patch degrades gracefully when per-image rootfs files are absent.
func (fcr *Runtime) imageRootfsFor(image string) string {
	if fcr.ImageRootfsDir == "" || image == "" {
		return fcr.FileSystemPath
	}
	key := imageRootfsKey(image)
	candidate := filepath.Join(fcr.ImageRootfsDir, "rootfs-"+key+".ext4")
	if _, err := os.Stat(candidate); err == nil {
		logrus.Infof("[BENCH] per-image rootfs for %s -> %s", image, candidate)
		return candidate
	}
	logrus.Warnf("no per-image rootfs for %s (looked for %s); using default %s",
		image, candidate, fcr.FileSystemPath)
	return fcr.FileSystemPath
}

// imageRootfsKey preserves immutable image identity in benchmark rootfs names.
// Tag references retain the legacy per-repository key for compatibility;
// digest references use repo-fullDigest so two task-specific images from the
// same repository never collapse onto one representative filesystem.
func imageRootfsKey(image string) string {
	ref := image
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		ref = ref[i+1:]
	}
	if i := strings.Index(ref, "@sha256:"); i >= 0 {
		repo := ref[:i]
		digest := ref[i+len("@sha256:"):]
		if repo != "" && digest != "" {
			return repo + "-" + digest
		}
	}
	if i := strings.Index(ref, ":"); i >= 0 {
		ref = ref[:i]
	}
	return ref
}

func (fcr *Runtime) createVMCS(image string) *VMControlStructure {
	sandboxID := fmt.Sprintf("firecracker-%d", fcr.idGenerator.Int())

	// Benchmark-time patch: per-VM, per-image rootfs copy. The source rootfs
	// is selected by imageRootfsFor(in.Image) — the SWE-bench repo the lane
	// was recorded against — and copied per VM (cp --sparse=always) so each
	// VM gets its own writable filesystem (ext4 has no multi-writer support,
	// which is why Dirigent's original shared rootfs is read-only). On the
	// benchmark XFS volume this is a metadata-only CoW reflink; snapshots still
	// work because the clone is identical to the source before user writes.
	sourcePath := fcr.imageRootfsFor(image)

	// Keep the per-VM clone on the same filesystem as its exact source so XFS
	// can create a metadata-only CoW reflink. /tmp is commonly a different
	// ext4 filesystem and silently turns this into a multi-GiB byte copy.
	instanceDir := filepath.Join(filepath.Dir(sourcePath), ".instances")
	_ = os.MkdirAll(instanceDir, 0o755)
	perVMPath := filepath.Join(instanceDir, fmt.Sprintf("rootfs-%s.ext4", sandboxID))
	ownsRootfs := true
	if out, err := exec.Command("cp", "--reflink=always", "--sparse=auto", sourcePath, perVMPath).CombinedOutput(); err != nil {
		// Preserve upstream compatibility for non-benchmark roots. The benchmark
		// fails closed by checking logs for this fallback before accepting a run.
		fallback := filepath.Join(os.TempDir(), fmt.Sprintf("rootfs-%s.ext4", sandboxID))
		if copyErr := exec.Command("cp", "--sparse=always", sourcePath, fallback).Run(); copyErr != nil {
			logrus.Warnf("Failed to reflink rootfs for %s (%v: %s) and fallback copy failed (%v); using shared read-only", sandboxID, err, strings.TrimSpace(string(out)), copyErr)
			perVMPath = sourcePath
			ownsRootfs = false
		} else {
			logrus.Warnf("[BENCH] reflink unavailable for %s (%v: %s); used byte-copy fallback %s", sandboxID, err, strings.TrimSpace(string(out)), fallback)
			perVMPath = fallback
		}
	} else {
		logrus.Infof("[BENCH] reflink rootfs for %s (%s) -> %s", sandboxID, sourcePath, perVMPath)
	}

	return &VMControlStructure{
		Context: context.Background(),

		KernelPath:     fcr.KernelPath,
		FileSystemPath: perVMPath,
		OwnsRootfs:     ownsRootfs,

		SandboxID: sandboxID,
	}
}

// cleanupPerVMRootfs deletes the per-VM rootfs copy if it is not the
// shared base (benchmark-time patch — see createVMCS).
func (fcr *Runtime) cleanupPerVMRootfs(vmcs *VMControlStructure) {
	if vmcs.OwnsRootfs {
		if err := os.Remove(vmcs.FileSystemPath); err != nil {
			logrus.Warnf("Failed to delete per-VM rootfs %s: %v", vmcs.FileSystemPath, err)
		}
	}
}

func createMetadata(in *proto.ServiceInfo, vmcs *VMControlStructure) *managers.Metadata {
	return &managers.Metadata{
		ServiceName: in.Name,

		RuntimeMetadata: FirecrackerMetadata{
			VMCS: vmcs,
		},

		IP:        vmcs.NetworkConfiguration.TapInternalIP,
		GuestPort: int(in.PortForwarding.GuestPort),

		ExitStatusChannel: make(chan uint32),
	}
}

func (fcr *Runtime) CreateSandbox(ctx context.Context, in *proto.ServiceInfo) (*proto.SandboxCreationStatus, error) {
	start := time.Now()

	vmcs := fcr.createVMCS(in.Image)

	startFindSnapshot := time.Now()
	snapshot, _ := fcr.SnapshotManager.FindSnapshot(in.Image)
	if snapshot != nil {
		logrus.Infof("Snapshot found for image %s", in.Image)
	}
	findSnapshotDuration := time.Since(startFindSnapshot)

	err, netCreateDuration, vmCreateDuration, vmStartDuration := StartFirecrackerVM(fcr.NetworkManager, vmcs, fcr.VMDebugMode, snapshot)
	if err != nil {
		// resource deallocation already done in StartFirecrackerVM
		fcr.cleanupPerVMRootfs(vmcs)
		return &proto.SandboxCreationStatus{Success: false}, err
	}

	startConfigureMonitoring := time.Now()
	metadata := createMetadata(in, vmcs)
	metadata.HostPort = containerd.AssignRandomPort()
	metadata.IP = vmcs.NetworkConfiguration.ExposedIP

	// VM process monitoring
	vmPID, err := vmcs.VM.PID()
	if err != nil {
		fcr.NetworkManager.GiveUpNetwork(vmcs.NetworkConfiguration)
		containerd.UnassignPort(metadata.HostPort)
		fcr.cleanupPerVMRootfs(vmcs)

		logrus.Debugf("Failed to get PID of the virtual machine - %v", err)
		return &proto.SandboxCreationStatus{Success: false}, err
	}

	fcr.SandboxManager.AddSandbox(vmcs.SandboxID, metadata)
	fcr.ProcessMonitor.AddChannel(uint32(vmPID), metadata.ExitStatusChannel)
	configureMonitoringDuration := time.Since(startConfigureMonitoring)

	// port forwarding
	iptablesStart := time.Now()
	managers.AddRules(fcr.IPT, metadata.HostPort, metadata.IP, metadata.GuestPort)
	iptablesDuration := time.Since(iptablesStart)

	// Start a TCP forwarder for localhost->VM traffic (replaces iptables
	// OUTPUT DNAT which fails on Linux 6.x — see forwarder.go).
	fwd, fwdErr := newTCPForwarder(fmt.Sprintf("127.0.0.1:%d", metadata.HostPort), fmt.Sprintf("%s:%d", metadata.IP, metadata.GuestPort))
	if fwdErr != nil {
		logrus.Errorf("Failed to start TCP forwarder for sandbox %s: %v", vmcs.SandboxID, fwdErr)
	} else {
		fcr.forwarderMutex.Lock()
		fcr.forwarders[vmcs.SandboxID] = fwd
		fcr.forwarderMutex.Unlock()
	}

	go containerd.WatchExitChannel(fcr.cpApi, metadata, func(metadata *managers.Metadata) string {
		return metadata.RuntimeMetadata.(FirecrackerMetadata).VMCS.SandboxID
	})

	in.PortForwarding.HostPort = int32(metadata.HostPort)

	logrus.Infof("[BENCH] create %s: before readiness probe (ipt=%v)", vmcs.SandboxID, iptablesDuration)

	// blocking call
	timeToPass, passed := managers.SendReadinessProbe(fmt.Sprintf("localhost:%d", metadata.HostPort))

	logrus.Infof("[BENCH] create %s: readiness probe passed=%v took=%v", vmcs.SandboxID, passed, timeToPass)

	// create a snapshot for the service if it does not exist
	startSnapshotCreation := time.Now()
	if passed && fcr.UseSnapshots && !fcr.SnapshotManager.Exists(in.Image) {
		ok, paths := CreateVMSnapshot(ctx, vmcs)

		if !ok {
			logrus.Warn("Due to failure, bypassing snapshot creation for image ", in.Image)
		} else {
			fcr.SnapshotManager.AddSnapshot(in.Image, paths)

			logrus.Debug("Snapshot successfully created for image ", in.Image)
		}

		err = vmcs.VM.ResumeVM(ctx)
		if err != nil {
			logrus.Errorf("Failed to create a sandbox %s due to error resuming virtual machine.", vmcs.SandboxID)
			passed = false // let the following code below take care of deletion
		}
	}
	snapshotCreationDuration := time.Since(startSnapshotCreation)

	logrus.Infof("[BENCH] create %s: after snapshot block passed=%v useSnap=%v", vmcs.SandboxID, passed, fcr.UseSnapshots)

	if passed {
		logrus.Infof("[BENCH] create %s: RETURNING success", vmcs.SandboxID)
		return &proto.SandboxCreationStatus{
			Success:      true,
			ID:           vmcs.SandboxID,
			PortMappings: in.PortForwarding,
			LatencyBreakdown: &proto.SandboxCreationBreakdown{
				Total:               durationpb.New(time.Since(start)),
				ImageFetch:          durationpb.New(0),
				SandboxCreate:       durationpb.New(vmCreateDuration),
				NetworkSetup:        durationpb.New(netCreateDuration),
				SandboxStart:        durationpb.New(vmStartDuration),
				ReadinessProbing:    durationpb.New(timeToPass),
				Iptables:            durationpb.New(iptablesDuration),
				SnapshotCreation:    durationpb.New(snapshotCreationDuration),
				ConfigureMonitoring: durationpb.New(configureMonitoringDuration),
				FindSnapshot:        durationpb.New(findSnapshotDuration),
			},
		}, nil
	} else {
		_, _ = fcr.DeleteSandbox(context.Background(), &proto.SandboxID{ID: vmcs.SandboxID})

		return &proto.SandboxCreationStatus{
			Success: false,
			ID:      vmcs.SandboxID,
		}, nil
	}
}

func CreateVMSnapshot(ctx context.Context, vmcs *VMControlStructure) (bool, *SnapshotMetadata) {
	err := vmcs.VM.PauseVM(ctx)
	if err != nil {
		logrus.Error("Error pausing virtual machine ", vmcs.SandboxID)
		return false, nil
	}

	snapshotDir := filepath.Join(os.TempDir(), "snapshots")

	err = os.MkdirAll(snapshotDir, os.ModePerm)
	if err != nil {
		logrus.Error("Error creating a directory for snapshot storage")
		return false, nil
	}

	snapshotPaths := &SnapshotMetadata{
		MemoryPath:   filepath.Join(snapshotDir, fmt.Sprintf("memory-firecracker-%s", vmcs.SandboxID)),
		SnapshotPath: filepath.Join(snapshotDir, fmt.Sprintf("snapshot-firecracker-%s", vmcs.SandboxID)),
	}

	err = vmcs.VM.CreateSnapshot(ctx, snapshotPaths.MemoryPath, snapshotPaths.SnapshotPath)
	if err != nil {
		logrus.Error("Error creating a snapshot out of virtual machine ", vmcs.SandboxID)
		return false, nil
	}

	return true, snapshotPaths
}

func (fcr *Runtime) DeleteSandbox(_ context.Context, in *proto.SandboxID) (*proto.ActionStatus, error) {
	metadata := fcr.SandboxManager.DeleteSandbox(in.ID)
	if metadata == nil {
		logrus.Errorf("Error while deleting sandbox from the manager. Invalid name %s.", in.ID)
		return &proto.ActionStatus{Success: false}, nil
	}

	start := time.Now()

	sandboxMetadata := metadata.RuntimeMetadata.(FirecrackerMetadata)

	// stop the TCP forwarder for this sandbox
	fcr.forwarderMutex.Lock()
	if fwd, ok := fcr.forwarders[in.ID]; ok {
		fwd.Close()
		delete(fcr.forwarders, in.ID)
	}
	fcr.forwarderMutex.Unlock()

	// delete networking rules
	managers.DeleteRules(fcr.IPT, metadata.HostPort, metadata.IP, metadata.GuestPort)
	containerd.UnassignPort(metadata.HostPort)
	logrus.Debug("IP tables configuration (remove rule(s)) took ", time.Since(start).Microseconds(), " μs")

	// destroy the VM
	err := StopFirecrackerVM(sandboxMetadata.VMCS)
	if err != nil {
		logrus.Errorf("Error deleting a sandbox - %v", err)
	}

	// delete the network associated with the VM
	fcr.NetworkManager.GiveUpNetwork(sandboxMetadata.VMCS.NetworkConfiguration)
	// delete Firecracker logs
	deleteLogs(sandboxMetadata.VMCS)

	// Benchmark-time patch: delete the per-VM rootfs copy (see
	// createVMCS / cleanupPerVMRootfs in runtime.go).
	fcr.cleanupPerVMRootfs(sandboxMetadata.VMCS)

	logrus.Debug("Sandbox deletion took ", time.Since(start).Microseconds(), " μs")
	return &proto.ActionStatus{Success: true}, nil
}

func (fcr *Runtime) ListEndpoints(_ context.Context, _ *emptypb.Empty) (*proto.EndpointsList, error) {
	return fcr.SandboxManager.ListEndpoints()
}

func (fcr *Runtime) ValidateHostConfig() bool {
	// Check for KVM access
	err := unix.Access("/dev/kvm", unix.W_OK)
	if err != nil {
		logrus.Errorf("KVM access denied - %v", err)
		return false
	}

	return true
}

func DeleteAllSnapshots() {
	// don't handle error because the directory may not exist
	_ = os.RemoveAll(filepath.Join(os.TempDir(), "snapshots"))
}
