package store

import (
	"fmt"
	"os"
	"strconv"
)

// Lock is an exclusive, process-lifetime lock on the data directory, so
// only one server instance can run on it. The OS releases it when the
// process dies, so a crash never leaves a stale lock behind (except on
// platforms that use the fallback implementation).
type Lock struct {
	path    string
	release func() error
}

// AcquireLock takes the lock or fails immediately if it is held.
func AcquireLock(path string) (*Lock, error) {
	rel, err := lockFile(path)
	if err != nil {
		return nil, fmt.Errorf("data directory is locked by another trove process (%s): %w", path, err)
	}
	return &Lock{path: path, release: rel}, nil
}

// Release frees the lock.
func (l *Lock) Release() error {
	if l == nil || l.release == nil {
		return nil
	}
	err := l.release()
	l.release = nil
	return err
}

func pidString() []byte { return []byte(strconv.Itoa(os.Getpid()) + "\n") }
