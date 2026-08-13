//go:build linux

package localdiagnosis

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
)

type osProcFS struct{ root string }

func NewOSProcFS() ProcFS { return osProcFS{root: "/proc"} }

func (p osProcFS) full(name string) string { return filepath.Join(p.root, filepath.FromSlash(name)) }

func (p osProcFS) ReadFile(name string) ([]byte, error) {
	f, err := os.Open(p.full(name))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxProcFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxProcFileBytes {
		return nil, os.ErrInvalid
	}
	return data, nil
}

func (p osProcFS) ReadDir(name string) ([]string, error) {
	dir, err := os.Open(p.full(name))
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	limit := maxFDCount
	if name == "" {
		limit = maxProcessCount
	}
	entries, err := dir.Readdirnames(limit + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return entries, nil
}

func (p osProcFS) Readlink(name string) (string, error) { return os.Readlink(p.full(name)) }

func (p osProcFS) StatInode(name string) (uint64, error) {
	info, err := os.Stat(p.full(name))
	if err != nil {
		return 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, syscall.EINVAL
	}
	return uint64(stat.Ino), nil
}

func Collect(port uint16) Inventory { return collectWithProcFS(NewOSProcFS(), port) }

func CollectWithProcFS(fs ProcFS, port uint16) Inventory { return collectWithProcFS(fs, port) }

func AttributeWithProcFS(fs ProcFS, listeners []Listener) Attribution {
	return attributeWithProcFS(fs, listeners)
}
