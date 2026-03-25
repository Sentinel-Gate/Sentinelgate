//go:build windows

package state

import "golang.org/x/sys/windows"

// flockLock acquires an exclusive file lock on Windows using LockFileEx.
// This blocks until the lock is available, matching Unix flock behavior.
func flockLock(fd uintptr) error {
	var ol windows.Overlapped
	return windows.LockFileEx(windows.Handle(fd), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol)
}

// flockUnlock releases the file lock on Windows using UnlockFileEx.
func flockUnlock(fd uintptr) error {
	var ol windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(fd), 0, 1, 0, &ol)
}
