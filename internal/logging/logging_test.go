package logging

import "testing"

func TestInitVerbose(t *testing.T) {
	// Smoke test: should not panic.
	Init(true)
}

func TestInitQuiet(t *testing.T) {
	Init(false)
}
