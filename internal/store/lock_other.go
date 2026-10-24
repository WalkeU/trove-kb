//go:build !linux && !darwin && !freebsd && !windows

package store

import (
	"os"
)

// Fallback: exclusive create. A crash leaves the file behind and it must
// be removed by hand after making sure no trove process is running.
func lockFile(path string) (func() error, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	_, _ = f.Write(pidString())
	return func() error {
		f.Close()
		return os.Remove(path)
	}, nil
}
