package firecracker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCleanupPerVMRootfsPreservesBorrowedSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.ext4")
	if err := os.WriteFile(path, []byte("rootfs"), 0o600); err != nil {
		t.Fatal(err)
	}

	(&Runtime{}).cleanupPerVMRootfs(&VMControlStructure{
		FileSystemPath: path,
		OwnsRootfs:     false,
	})

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("borrowed rootfs was removed: %v", err)
	}
}

func TestCleanupPerVMRootfsRemovesOwnedCopy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sandbox.ext4")
	if err := os.WriteFile(path, []byte("rootfs"), 0o600); err != nil {
		t.Fatal(err)
	}

	(&Runtime{}).cleanupPerVMRootfs(&VMControlStructure{
		FileSystemPath: path,
		OwnsRootfs:     true,
	})

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("owned rootfs still exists: %v", err)
	}
}

func TestImageRootfsKeyPreservesDigestIdentity(t *testing.T) {
	got := imageRootfsKey("ghcr.io/swe-images/pandas_final@sha256:abcdef012345")
	if want := "pandas_final-abcdef012345"; got != want {
		t.Fatalf("imageRootfsKey() = %q, want %q", got, want)
	}
}

func TestImageRootfsKeyKeepsLegacyTagMapping(t *testing.T) {
	got := imageRootfsKey("ghcr.io/swe-images/pandas_final:task-commit")
	if want := "pandas_final"; got != want {
		t.Fatalf("imageRootfsKey() = %q, want %q", got, want)
	}
}

func TestImageRootfsForSelectsExactDigestFile(t *testing.T) {
	dir := t.TempDir()
	exact := filepath.Join(dir, "rootfs-pandas_final-abcdef012345.ext4")
	if err := os.WriteFile(exact, []byte("rootfs"), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{ImageRootfsDir: dir, FileSystemPath: "fallback.ext4"}
	if got := runtime.imageRootfsFor("ghcr.io/swe-images/pandas_final@sha256:abcdef012345"); got != exact {
		t.Fatalf("imageRootfsFor() = %q, want %q", got, exact)
	}
}
