/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

	Library Author: Nguyen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details
    (c) 2013 COSEINC. All Rights Reserved.
*/

package gapstone

import (
	"log"
	"testing"
)

var x86Skip = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92"

func myCallback(data []byte, offset int, ud interface{}) int {
	log.Printf("Got len %v, offset %v, userdata: %v", len(data), offset, ud)
	return 2
}

func TestSkipData(t *testing.T) {

	var maj, min int
	if ver, err := New(0, 0); err == nil {
		maj, min = ver.Version()
		ver.Close()
	}

	t.Logf("Skipdata Test. Capstone Version: %v.%v", maj, min)

	engine, err := New(
		CS_ARCH_X86,
		CS_MODE_32,
	)
	if err != nil {
		t.Fatalf("Unable to open engine: %v", err)
	}
	defer engine.Close()

	engine.SkipDataStart(
		SkipDataConfig{
			Mnemonic: "db",
			Callback: myCallback,
			UserData: 42,
		},
	)

	insns, err := engine.Disasm(
		[]byte(x86Skip), // code buffer
		0x10000,         // starting address
		0,               // insns to disassemble, 0 for all
	)

	if err == nil {
		log.Printf("Disasm:\n")
		for _, insn := range insns {
			log.Printf("0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
		}
		return
	}
	engine.SkipDataStop()
}
