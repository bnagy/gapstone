package gapstone

import "testing"

const EXPECTED_MAJ = 2
const EXPECTED_MIN = 1

func TestVersion(t *testing.T) {
	if c, err := New(0, 0); err == nil {
		maj, min := c.Version()
		if maj == EXPECTED_MAJ && min == EXPECTED_MIN {
			t.Logf("Libary version %v.%v, OK.", maj, min)
		} else {
			t.Errorf(
				"Version mismatch. These bindings for %v.%v, Installed lib %v.%v",
				EXPECTED_MAJ,
				EXPECTED_MIN,
				maj,
				min,
			)
		}

		c.Close()
	}
}
