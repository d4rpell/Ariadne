//go:build unix

package main

import "syscall"

// makeFIFO creates a POSIX FIFO so the pre-open type check can be exercised
// with the special file that would otherwise block inside Open.
func makeFIFO(path string) error {
	return syscall.Mkfifo(path, 0o600)
}
