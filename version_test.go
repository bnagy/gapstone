package gapstone

import "testing"

func TestVersion(t *testing.T) {
	if c, err := New(0, 0); err == nil {
		maj, min := c.Version()
		if maj == checks.Maj() && min == checks.Min() {
			t.Logf("Libary version %v.%v, OK.", maj, min)
		} else {
			t.Errorf(
				"Version mismatch. These bindings for %v.%v, Installed lib %v.%v",
				checks.Maj(),
				checks.Min(),
				maj,
				min,
			)
		}
		err = c.Close()
		if err != ErrOK {
			t.Errorf("Failed to close: %v", err)
		}

		return
	}
	t.Errorf("Failed to initialize engine.")
}
