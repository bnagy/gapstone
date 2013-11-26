capstone-go
===========

Gapstone is a Go binding for the Capstone disassembly library.

BETA BETA BETA BETA
---
+ This repository name is chosen for clarity. The package name is gapstone
+ __Don't commit here or I will cut you__

  Commit issues or fork ( it stays private ) and send me a pull request.

To install:
```bash
go get -u github.com/aquynh/capstone-go
```

Take a look at the examples *_test.go

Maybe something like:
```go
package main

import "github.com/aquynh/capstone-go"
import "fmt"

func main() {

    if ver, err := gapstone.New(0, 0); err == nil {
        maj, min := ver.Version()
        fmt.Printf("Adhoc Test. Capstone Version: %v.%v\n", maj, min)
        fmt.Printf("Errno: %v\n", ver.Errno().Error())
        if ver.Errno() == gapstone.ErrOK {
            fmt.Printf("All is well.\n")
        }
        ver.Close()
    }
}
```



    Library Author: Nguyen Anh Quynh
    Binding Author: Ben Nagy
    License: BSD style - see LICENSE file for details

    (c) 2013 COSEINC. All Rights Reserved.
