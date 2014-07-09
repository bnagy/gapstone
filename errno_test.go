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

func TestErrno(t *testing.T) {
	if ver, err := New(0, 0); err == nil {
		maj, min := ver.Version()
		t.Logf("Adhoc Test. Capstone Version: %v.%v", maj, min)
		t.Logf("Errno: %v", ver.Errno().Error())
		if ver.Errno() == ErrOK {
			t.Logf("All is well.")
		}
		if ver.Support(CS_ARCH_ALL) {
			t.Logf("Engine supports all archs")
		}
		ver.Close()
	}
}
