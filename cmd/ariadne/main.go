package main

import "os"

// Process adapter of ADR-0023 §3: it hands argv and the streams to the runner
// and applies the exit code. It contains no business logic, opens no path by
// itself and never re-executes anything.
func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
