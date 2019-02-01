// +build go1.7

package gapstone

import (
	"bytes"
	"testing"
)

func benchmarkBasicX86(scale int, b *testing.B) {
	engine, err := New(CS_ARCH_X86, CS_MODE_32)

	if err != nil {
		b.Fatalf("Failed to initialize engine: %v", err)
	}
	defer engine.Close()

	var testCode bytes.Buffer
	var x86Code32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34" +
		"\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91" +
		"\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00" +
		"\x8d\x87\x89\x67\x00\x00\xb4\xc6"
	for i := 0; i < scale; i++ {
		testCode.WriteString(x86Code32)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		insns, err := engine.Disasm(
			testCode.Bytes(), // code buffer
			0x10000,          // starting address
			0,                // insns to disassemble, 0 for all
		)

		if err != nil {
			b.Fatalf("Disassembly error: %v", err)
		}
		var count uint = 0
		for _, insn := range insns {
			count += insn.Id
		}
	}
}
func BenchmarkBasicX86Small(b *testing.B)  { benchmarkBasicX86(1, b) }
func BenchmarkBasicX86Medium(b *testing.B) { benchmarkBasicX86(100, b) }
func BenchmarkBasicX86Large(b *testing.B)  { benchmarkBasicX86(10000, b) }
func BenchmarkBasicX86XLarge(b *testing.B) { benchmarkBasicX86(1000000, b) }

func benchmarkIterX86(scale int, b *testing.B) {
	engine, err := New(CS_ARCH_X86, CS_MODE_32)

	if err != nil {
		b.Fatalf("Failed to initialize engine: %v", err)
	}
	defer engine.Close()

	var testCode bytes.Buffer
	var x86Code32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34" +
		"\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91" +
		"\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00" +
		"\x8d\x87\x89\x67\x00\x00\xb4\xc6"
	for i := 0; i < scale; i++ {
		testCode.WriteString(x86Code32)
	}

	b.ResetTimer()
	for n := 0; n < b.N; n++ {
		insns := engine.DisasmIter(
			testCode.Bytes(), // code buffer
			0x10000,          // starting address
		)

		var count uint = 0
		for insn := range insns {
			count += insn.Id
		}
	}
}
func BenchmarkIterX86Small(b *testing.B)  { benchmarkIterX86(1, b) }
func BenchmarkIterX86Medium(b *testing.B) { benchmarkIterX86(100, b) }
func BenchmarkIterX86Large(b *testing.B)  { benchmarkIterX86(10000, b) }
func BenchmarkIterX86XLarge(b *testing.B) { benchmarkIterX86(1000000, b) }
