package firecracker

import (
	"io"
	"net"
	"sync"

	"github.com/sirupsen/logrus"
)

// tcpForwarder listens on a local address (typically 127.0.0.1:<hostPort>)
// and forwards each accepted TCP connection to a remote address (typically
// <exposedIP>:<guestPort>).
//
// It replaces the iptables OUTPUT-DNAT rule that Dirigent originally used for
// localhost→VM traffic.  On Linux 6.x, ip_route_me_harder() — invoked after
// DNAT in the OUTPUT chain — cannot re-route a locally-generated packet whose
// source is 127.0.0.1 onto a non-loopback interface (the veth that leads to
// the VM's netns).  The DNAT'd packet is silently dropped, so the readiness
// probe (curl localhost:<hostPort>/health) never reaches the VM.
//
// A userspace forwarder sidesteps the issue: it accepts the client connection
// on 127.0.0.1:<hostPort>, then dials <exposedIP>:<guestPort> as a fresh
// locally-generated connection.  The kernel selects a valid source address
// (the host-side veth IP) for the new connection, and the existing NETNS
// PREROUTING DNAT + POSTROUTING SNAT rules handle the rest of the path to the
// VM and back.
type tcpForwarder struct {
	listener net.Listener
	wg       sync.WaitGroup
	closed   bool
	mu       sync.Mutex
}

// newTCPForwarder starts listening on listenAddr and returns a forwarder that
// will connect each accepted client to dialAddr.
func newTCPForwarder(listenAddr, dialAddr string) (*tcpForwarder, error) {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	f := &tcpForwarder{listener: ln}
	f.wg.Add(1)
	go f.acceptLoop(dialAddr)
	logrus.Debugf("TCP forwarder: %s -> %s", listenAddr, dialAddr)
	return f, nil
}

func (f *tcpForwarder) acceptLoop(dialAddr string) {
	defer f.wg.Done()
	for {
		conn, err := f.listener.Accept()
		if err != nil {
			f.mu.Lock()
			done := f.closed
			f.mu.Unlock()
			if done {
				return
			}
			logrus.Errorf("forwarder accept error: %v", err)
			return
		}
		f.wg.Add(1)
		go f.handle(conn, dialAddr)
	}
}

func (f *tcpForwarder) handle(client net.Conn, dialAddr string) {
	defer f.wg.Done()
	defer client.Close()

	remote, err := net.Dial("tcp", dialAddr)
	if err != nil {
		logrus.Errorf("forwarder dial error (%s): %v", dialAddr, err)
		return
	}
	defer remote.Close()

	var pair sync.WaitGroup
	pair.Add(2)
	go func() {
		defer pair.Done()
		io.Copy(remote, client)
		if tc, ok := remote.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	go func() {
		defer pair.Done()
		io.Copy(client, remote)
		if tc, ok := client.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	pair.Wait()
}

// Close stops accepting new connections and waits for all active
// connections to finish.
func (f *tcpForwarder) Close() {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	f.listener.Close()
	f.wg.Wait()
}
