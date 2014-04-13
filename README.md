gapstone
====

Gapstone is a Go binding for the Capstone disassembly library.

RECENT CHANGES
===

Changed the way libs are found, which reverted the change to use pkg-config. If
you can't use go get for your platform, please check the cflags / ldflags trick
we used for freebsd and submit a patch for your OS.

( FROM THE CAPSTONE README )

Capstone is a disassembly framework with the target of becoming the ultimate
disasm engine for binary analysis and reversing in the security community.

Created by Nguyen Anh Quynh, then developed and maintained by a small community,
Capstone offers some unparalleled features:

- Support multiple hardware architectures: ARM, ARM64 (aka ARMv8), Mips, X86, PPC, Sparc & SystemZ

- Having clean/simple/lightweight/intuitive architecture-neutral API.

- Provide details on disassembled instruction (called “decomposer” by others).

- Provide semantics of the disassembled instruction, such as list of implicit
     registers read & written.

- Implemented in pure C language, with lightweight wrappers for C++, Python,
     Ruby, OCaml, C#, Java and Go available.

- Native support for Windows & *nix platforms (MacOSX, Linux & *BSD confirmed).

- Thread-safe by design.

- Distributed under the open source BSD license.

To install:
----

First install the capstone library from either https://github.com/aquynh/capstone
or http://www.capstone-engine.org

Then, assuming you have set up your Go environment according to the docs, just:
```bash
go get -u github.com/bnagy/gapstone
```

Tests are provided. You should probably run them.
```
cd $GOPATH/src/github.com/bnagy/gapstone
go test
```

To start writing code:
----

Take a look at the examples *_test.go

Here's "Hello World":
```go
package main

import "github.com/bnagy/gapstone"
import "log"

func main() {

    engine, err := gapstone.New(
        gapstone.CS_ARCH_X86,
        gapstone.CS_MODE_32,
    )

    if err == nil {

        defer engine.Close()

        maj, min := engine.Version()
        log.Printf("Hello Capstone! Version: %v.%v\n", maj, min)

        var x86Code32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34" +
            "\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91" +
            "\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00" +
            "\x8d\x87\x89\x67\x00\x00\xb4\xc6"

        insns, err := engine.Disasm(
            []byte(x86Code32), // code buffer
            0x10000,           // starting address
            0,                 // insns to disassemble, 0 for all
        )

        if err == nil {
            log.Printf("Disasm:\n")
            for _, insn := range insns {
                log.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
            }
            return
        }
        log.Fatalf("Disassembly error: %v", err)
    }
    log.Fatalf("Failed to initialize engine: %v", err)
}
```

Autodoc is available at http://godoc.org/github.com/bnagy/gapstone

Contributing
----

If you feel like chipping in, especially with better tests or examples, fork and send me a pull req.


```
Library Author: Nguyen Anh Quynh
Binding Author: Ben Nagy
License: BSD style - see LICENSE file for details

(c) 2013 COSEINC. All Rights Reserved.
```
