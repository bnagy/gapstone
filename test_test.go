package gapstone

import "testing"
import "bytes"
import "fmt"
import "io/ioutil"

const BASIC_X86_CODE16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
const BASIC_X86_CODE32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
const BASIC_X86_CODE64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00"
const BASIC_ARM_CODE = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
const BASIC_ARM_CODE2 = "\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3"
const BASIC_THUMB_CODE = "\x70\x47\xeb\x46\x83\xb0\xc9\x68"
const BASIC_THUMB_CODE2 = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
const BASIC_MIPS_CODE = "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56"
const BASIC_MIPS_CODE2 = "\x56\x34\x21\x34\xc2\x17\x01\x00"
const BASIC_ARM64_CODE = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9"

var basic_tests = platforms{
	{
		CS_ARCH_X86,
		CS_MODE_16,
		BASIC_X86_CODE16,
		"X86 16bit (Intel syntax)",
	},
	{
		CS_ARCH_X86,
		CS_MODE_32 + CS_MODE_SYNTAX_ATT,
		BASIC_X86_CODE32,
		"X86 32bit (ATT syntax)",
	},
	{
		CS_ARCH_X86,
		CS_MODE_32,
		BASIC_X86_CODE32,
		"X86 32 (Intel syntax)",
	},
	{
		CS_ARCH_X86,
		CS_MODE_64,
		BASIC_X86_CODE64,
		"X86 64 (Intel syntax)",
	},
	{
		CS_ARCH_ARM,
		CS_MODE_ARM,
		BASIC_ARM_CODE,
		"ARM",
	},
	{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		BASIC_THUMB_CODE2,
		"THUMB-2",
	},
	{
		CS_ARCH_ARM,
		CS_MODE_ARM,
		BASIC_ARM_CODE2,
		"ARM: Cortex-A15 + NEON",
	},
	{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		BASIC_THUMB_CODE,
		"THUMB",
	},
	{
		CS_ARCH_MIPS,
		CS_MODE_32 + CS_MODE_BIG_ENDIAN,
		BASIC_MIPS_CODE,
		"MIPS-32 (Big-endian)",
	},
	{
		CS_ARCH_MIPS,
		CS_MODE_64 + CS_MODE_LITTLE_ENDIAN,
		BASIC_MIPS_CODE2,
		"MIPS-64-EL (Little-endian)",
	},
	{
		CS_ARCH_ARM64,
		CS_MODE_ARM,
		BASIC_ARM64_CODE,
		"ARM-64",
	},
}

func TestTest(t *testing.T) {

	final := new(bytes.Buffer)
	spec_file := "test.SPEC"
	ver, err := New(0, 0)
	maj, min := ver.Version()
	ver.Close()
	t.Logf("Basic Test. Capstone Version: %v.%v", maj, min)
	for i, platform := range basic_tests {
		t.Logf("%2d> %s", i, platform.comment)
		engine, err := New(platform.arch, platform.mode)
		if err != nil {
			t.Errorf("Failed to initialize engine %v", err)
			return
		}
		defer engine.Close()
		insns, err := engine.Disasm([]byte(platform.code), OFFSET, 0)
		if err == nil {
			fmt.Fprintf(final, "****************\n")
			fmt.Fprintf(final, "Platform: %s\n", platform.comment)
			fmt.Fprintf(final, "Code: ")
			dumpHex([]byte(platform.code), final)
			fmt.Fprintf(final, "Disasm:\n")
			for _, insn := range insns {
				fmt.Fprintf(final, "0x%x:\t%s\t\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
			}
			fmt.Fprintf(final, "0x%x:\n", insns[len(insns)-1].Address+insns[len(insns)-1].Size)
			fmt.Fprintf(final, "\n")
		} else {
			t.Errorf("Disassembly error: %v\n", err)
		}

	}

	spec, err := ioutil.ReadFile(spec_file)
	if err != nil {
		t.Errorf("Cannot read spec file %v: %v", spec_file, err)
	}
	if fs := final.String(); string(spec) != fs {
		fmt.Println(fs)
		t.Errorf("Output failed to match spec!")
	} else {
		t.Logf("Clean diff with %v.\n", spec_file)
	}

}
