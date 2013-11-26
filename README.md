capstone-go
===========

Gapstone is a Go binding for the Capstone disassembly library.

---
+ This repository name is chosen for clarity. The package name is gapstone
+ Don't commit here or I will cut you
---

To install:
```bash
go get -u github.com/aquynh/capstone-go
```

Take a look at the examples *_test.go

Maybe something like:
```go
import "gapstone"

func main {

    if ver, err := gapstone.New(0, 0); err == nil {
        maj, min := ver.Version()
        t.Logf("Adhoc Test. Capstone Version: %v.%v", maj, min)
        t.Logf("Errno: %v", ver.Errno().Error())
        if ver.Errno() == gapstone.ErrOK {
            t.Logf("All is well.")
        }
        ver.Close()
    }
}
```



    Library Author: Nguyen Anh Quynh
    Binding Author: Ben Nagy
    License: BSD style - see LICENSE file for details

    (c) 2013 COSEINC. All Rights Reserved.
