//go:build !unix

package main

import "errors"

// makeFIFO reports the unsupported arrangement: the FIFO case is exercised on
// the platforms that can create one, and its absence never turns into a pass.
func makeFIFO(string) error {
	return errors.New("FIFO not supported on this platform")
}
