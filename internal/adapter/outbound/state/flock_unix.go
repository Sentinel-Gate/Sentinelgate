//go:build !windows

package state

import "syscall"

// flockLock acquires an exclusive file lock (Unix implementation using flock).
func flockLock(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_EX)
}

// flockUnlock releases the file lock (Unix implementation using flock).
func flockUnlock(fd uintptr) error {
	return syscall.Flock(int(fd), syscall.LOCK_UN)
}
