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
		ver.Close()
	}
}
