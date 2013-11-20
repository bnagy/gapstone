package gapstone

import "testing"
import "fmt"

type platform struct {
	arch    Arch
	mode    Mode
	code    string
	comment string
}
type platforms []platform

const ARM_CODE = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"

var tests = platforms{
	platform{
		CS_ARCH_ARM,
		CS_MODE_ARM,
		ARM_CODE,
		"X86 32 (Intel syntax)",
	},
}

func TestBasic(t *testing.T) {
	for _, p := range tests {

		engine, err := New(p.arch, p.mode)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer engine.Close()

		insns, _ := engine.Disasm(p.code, 0x1000, 0)
		for _, insn := range insns {
			fmt.Println("Disassembly:", insn.Mnemonic, insn.OpStr)
			fmt.Println("Operands:", insn.Arm.OpCount)
		}

	}
}
