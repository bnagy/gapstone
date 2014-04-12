/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

	Library Author: Nguyen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details
    (c) 2013 COSEINC. All Rights Reserved.
*/

package gapstone

import "testing"

func TestVersion(t *testing.T) {
	if c, err := New(0, 0); err == nil {
		maj, min := c.Version()
		if maj == checks.Maj() && min == checks.Min() {
			t.Logf("Libary version %v.%v, OK.", maj, min)
			t.Logf("CAPSTONE_DIET: %v", dietMode)
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
