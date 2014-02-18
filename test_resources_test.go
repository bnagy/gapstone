package gapstone

import "bytes"
import "fmt"

type option struct {
	ty    uint
	value uint
}

type platform struct {
	arch    int
	mode    uint
	options []option
	code    string
	comment string
}
type platforms []platform

var address = uint64(0x1000)
var armCode = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
var armCode2 = "\xd1\xe8\x00\xf0\xf0\x24\x04\x07\x1f\x3c\xf2\xc0\x00\x00\x4f\xf0\x00\x01\x46\x6c"
var thumbCode = "\x70\x47\xeb\x46\x83\xb0\xc9\x68\x1f\xb1"
var thumbCode2 = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
var arm64Code = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b"
var x86Code64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00"
var x86Code16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
var x86Code32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
var mipsCode = "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56"
var mipsCode2 = "\x56\x34\x21\x34\xc2\x17\x01\x00"
var basicX86Code16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
var basicX86Code32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00"
var basicX86Code64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00"
var basicArmCode = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
var basicArmCode2 = "\x10\xf1\x10\xe7\x11\xf2\x31\xe7\xdc\xa1\x2e\xf3\xe8\x4e\x62\xf3"
var basicThumbCode = "\x70\x47\xeb\x46\x83\xb0\xc9\x68"
var basicThumbCode2 = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
var basicMipsCode = "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56"
var basicMipsCode2 = "\x56\x34\x21\x34\xc2\x17\x01\x00"
var basicArm64Code = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9"
var ppcCode = "\x80\x20\x00\x00\x80\x3f\x00\x00\x10\x43\x23\x0e\xd0\x44\x00\x80\x4c\x43\x22\x02\x2d\x03\x00\x80\x7c\x43\x20\x14\x7c\x43\x20\x93\x4f\x20\x00\x21\x4c\xc8\x00\x21"
var basic_tests = platforms{
	{
		CS_ARCH_X86,
		CS_MODE_16,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicX86Code16,
		"X86 16bit (Intel syntax)",
	},
	{
		CS_ARCH_X86,
		CS_MODE_32,
		[]option{{CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT}, {CS_OPT_DETAIL, CS_OPT_ON}},
		basicX86Code32,
		"X86 32bit (ATT syntax)",
	},
	{
		CS_ARCH_X86,
		CS_MODE_32,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicX86Code32,
		"X86 32 (Intel syntax)",
	},
	{
		CS_ARCH_X86,
		CS_MODE_64,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicX86Code64,
		"X86 64 (Intel syntax)",
	},
	{
		CS_ARCH_ARM,
		CS_MODE_ARM,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicArmCode,
		"ARM",
	},
	{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicThumbCode2,
		"THUMB-2",
	},
	{
		CS_ARCH_ARM,
		CS_MODE_ARM,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicArmCode2,
		"ARM: Cortex-A15 + NEON",
	},
	{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicThumbCode,
		"THUMB",
	},
	{
		CS_ARCH_MIPS,
		CS_MODE_32 + CS_MODE_BIG_ENDIAN,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicMipsCode,
		"MIPS-32 (Big-endian)",
	},
	{
		CS_ARCH_MIPS,
		CS_MODE_64 + CS_MODE_LITTLE_ENDIAN,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicMipsCode2,
		"MIPS-64-EL (Little-endian)",
	},
	{
		CS_ARCH_ARM64,
		CS_MODE_ARM,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		basicArm64Code,
		"ARM-64",
	},
	platform{
		CS_ARCH_PPC,
		CS_MODE_BIG_ENDIAN,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		ppcCode,
		"PPC-64",
	},
	platform{
		CS_ARCH_PPC,
		CS_MODE_BIG_ENDIAN,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}, {CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME}},
		ppcCode,
		"PPC-64, print register with number only",
	},
}

var arm_tests = platforms{
	platform{
		CS_ARCH_ARM,
		CS_MODE_ARM,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		armCode,
		"ARM",
	},
	platform{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		thumbCode,
		"Thumb",
	},
	platform{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		armCode2,
		"Thumb-mixed",
	},
	platform{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		thumbCode2,
		"Thumb-2",
	},
}

var arm64_tests = platforms{
	platform{
		CS_ARCH_ARM64,
		CS_MODE_ARM,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		arm64Code,
		"ARM-64",
	},
}

var mips_tests = platforms{
	platform{
		CS_ARCH_MIPS,
		CS_MODE_32 + CS_MODE_BIG_ENDIAN,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		mipsCode,
		"MIPS-32 (Big-endian)",
	},
	platform{
		CS_ARCH_MIPS,
		CS_MODE_64 + CS_MODE_LITTLE_ENDIAN,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		mipsCode2,
		"MIPS-64-EL (Little-endian)",
	},
}

var x86_tests = platforms{
	platform{
		CS_ARCH_X86,
		CS_MODE_16,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		x86Code16,
		"X86 16bit (Intel syntax)",
	},
	platform{
		CS_ARCH_X86,
		CS_MODE_32,
		[]option{{CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT}, {CS_OPT_DETAIL, CS_OPT_ON}},
		x86Code32,
		"X86 32 (AT&T syntax)",
	},
	platform{
		CS_ARCH_X86,
		CS_MODE_32,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		x86Code32,
		"X86 32 (Intel syntax)",
	},
	platform{
		CS_ARCH_X86,
		CS_MODE_64,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		x86Code64,
		"X86 64 (Intel syntax)",
	},
}

var ppc_tests = platforms{
	platform{
		CS_ARCH_PPC,
		CS_MODE_BIG_ENDIAN,
		[]option{{CS_OPT_DETAIL, CS_OPT_ON}},
		ppcCode,
		"PPC-64",
	},
}

func dumpHex(code []byte, buf *bytes.Buffer) {
	for _, b := range code {
		// This deliberately leaves a stray space at EOL to match the C tests.
		fmt.Fprintf(buf, "0x%.2x ", b)
	}
	fmt.Fprintf(buf, "\n")
}
