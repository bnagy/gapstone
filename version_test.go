package gapstone

import "testing"

func TestVersion(t *testing.T) {
	if c, err := New(0, 0); err == nil {
		defer c.Close()
		maj, min := c.Version()
		check := sanityChecks[0]
		if maj == check.maj && min == check.min {
			t.Logf("Libary version %v.%v, OK.", maj, min)
		} else {
			t.Errorf(
				"Version mismatch. These bindings for %v.%v, Installed lib %v.%v",
				check.maj,
				check.min,
				maj,
				min,
			)
		}
		return
	}
	t.Errorf("Failed to initialize engine.")
}
