//go:build windows

package store

import (
	"syscall"
)

func lockFile(path string) (func() error, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	// Share mode 0: no other handle can open the file while we hold it.
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ|syscall.GENERIC_WRITE, 0, nil,
		syscall.OPEN_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	var written uint32
	data := pidString()
	_ = syscall.SetEndOfFile(h)
	_ = syscall.WriteFile(h, data, &written, nil)
	return func() error { return syscall.CloseHandle(h) }, nil
}
