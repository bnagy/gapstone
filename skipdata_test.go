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
	"testing"
)

var x86Skip = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x00\x91\x92"
var thack *testing.T

type someRandomStruct struct {
	Foo int
	Bar string
	Baz float64
}

func myCallback(data []byte, offset int, ud interface{}) int {
	if ud.(someRandomStruct).Baz != 3.141 {
		thack.Errorf("error in userdata, want Baz: 3.141, got %v", ud.(someRandomStruct).Baz)
	}
	return 2
}

func TestFullConfig(t *testing.T) {

	t.Parallel()
	thack = t
	mnem := "NOTCODE"

	engine, err := New(
		CS_ARCH_X86,
		CS_MODE_32,
	)
	if err != nil {
		t.Fatalf("Unable to open engine: %v", err)
	}
	defer engine.Close()

	engine.SkipDataStart(
		&SkipDataConfig{
			Mnemonic: mnem,
			Callback: myCallback,
			UserData: someRandomStruct{Baz: 3.141},
		},
	)
	defer engine.SkipDataStop()

	insns, err := engine.Disasm(
		[]byte(x86Skip), // code buffer
		0x10000,         // starting address
		0,               // insns to disassemble, 0 for all
	)

	if err == nil {
		if len(insns) < 4 || insns[3].Mnemonic != mnem {
			t.Errorf("Want custom mnemonic %v, got %v", mnem, insns[3].Mnemonic)
		} else {
			t.Logf("SkipData with full config: [OK]\n")
		}
		// Erroneous extra call to SkipDataStop()
		engine.SkipDataStop()
		return
	}
	t.Errorf("Disassembly failed: %v", err)
}

func TestMnemonicOnly(t *testing.T) {

	t.Parallel()
	thack = t
	mnem := "rabbits"

	engine, err := New(
		CS_ARCH_X86,
		CS_MODE_32,
	)
	if err != nil {
		t.Fatalf("Unable to open engine: %v", err)
	}
	defer engine.Close()

	engine.SkipDataStart(
		&SkipDataConfig{
			Mnemonic: mnem,
		},
	)
	defer engine.SkipDataStop()

	insns, err := engine.Disasm(
		[]byte(x86Skip), // code buffer
		0x10000,         // starting address
		0,               // insns to disassemble, 0 for all
	)

	if err == nil {
		if len(insns) < 4 || insns[3].Mnemonic != mnem {
			t.Errorf("Want custom mnemonic %v, got %v", mnem, insns[3].Mnemonic)
		} else {
			t.Logf("SkipData with mnemonic only: [OK]\n")
		}
		return
	}
	t.Errorf("Disassembly failed: %v", err)

}

func TestCallbackOnly(t *testing.T) {

	t.Parallel()
	thack = t
	mnem := ".byte"

	engine, err := New(
		CS_ARCH_X86,
		CS_MODE_32,
	)
	if err != nil {
		t.Fatalf("Unable to open engine: %v", err)
	}
	defer engine.Close()

	engine.SkipDataStart(
		&SkipDataConfig{
			Callback: myCallback,
			UserData: someRandomStruct{Baz: 3.141},
		},
	)
	defer engine.SkipDataStop()

	insns, err := engine.Disasm(
		[]byte(x86Skip), // code buffer
		0x10000,         // starting address
		0,               // insns to disassemble, 0 for all
	)

	if err == nil {
		if len(insns) < 4 || insns[3].Mnemonic != mnem {
			t.Errorf("Want default mnemonic %v, got %v", mnem, insns[3].Mnemonic)
		} else {
			t.Logf("SkipData with callback only: [OK]\n")
		}
		return
	}
	t.Errorf("Disassembly failed: %v", err)

}
func TestNilConfig(t *testing.T) {

	t.Parallel()
	thack = t
	mnem := ".byte"

	engine, err := New(
		CS_ARCH_X86,
		CS_MODE_32,
	)
	if err != nil {
		t.Fatalf("Unable to open engine: %v", err)
	}
	defer engine.Close()

	engine.SkipDataStart(nil)
	defer engine.SkipDataStop()

	insns, err := engine.Disasm(
		[]byte(x86Skip), // code buffer
		0x10000,         // starting address
		0,               // insns to disassemble, 0 for all
	)

	if err == nil {
		if len(insns) < 4 || insns[3].Mnemonic != mnem {
			t.Errorf("Want default mnemonic %v, got %v", mnem, insns[3].Mnemonic)
		} else {
			t.Logf("SkipData with default: [OK]\n")
		}
		return
	}
	t.Errorf("Disassembly failed: %v", err)

}
