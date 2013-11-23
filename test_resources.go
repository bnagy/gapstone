package gapstone

import "bytes"
import "fmt"

type platform struct {
	arch    Arch
	mode    Mode
	code    string
	comment string
}
type platforms []platform

const OFFSET = 0x1000
const ARM_CODE = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
const ARM_CODE2 = "\xd1\xe8\x00\xf0\xf0\x24\x04\x07\x1f\x3c\xf2\xc0\x00\x00\x4f\xf0\x00\x01\x46\x6c"
const THUMB_CODE = "\x70\x47\xeb\x46\x83\xb0\xc9\x68\x1f\xb1"
const THUMB_CODE2 = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"
const ARM64_CODE = "\x21\x7c\x02\x9b\x21\x7c\x00\x53\x00\x40\x21\x4b\xe1\x0b\x40\xb9\x20\x04\x81\xda\x20\x08\x02\x8b"
const X86_CODE64 = "\x55\x48\x8b\x05\xb8\x13\x00\x00"
const X86_CODE16 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
const X86_CODE32 = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
const MIPS_CODE = "\x0C\x10\x00\x97\x00\x00\x00\x00\x24\x02\x00\x0c\x8f\xa2\x00\x00\x34\x21\x34\x56"
const MIPS_CODE2 = "\x56\x34\x21\x34\xc2\x17\x01\x00"

var arm_tests = platforms{
	platform{
		CS_ARCH_ARM,
		CS_MODE_ARM,
		ARM_CODE,
		"ARM",
	},
	platform{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		THUMB_CODE,
		"Thumb",
	},
	platform{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		ARM_CODE2,
		"Thumb-mixed",
	},
	platform{
		CS_ARCH_ARM,
		CS_MODE_THUMB,
		THUMB_CODE2,
		"Thumb-2",
	},
}

var arm64_tests = platforms{
	platform{
		CS_ARCH_ARM64,
		CS_MODE_ARM,
		ARM64_CODE,
		"ARM-64",
	},
}

var mips_tests = platforms{
	platform{
		CS_ARCH_MIPS,
		CS_MODE_32 + CS_MODE_BIG_ENDIAN,
		MIPS_CODE,
		"MIPS-32 (Big-endian)",
	},
	platform{
		CS_ARCH_MIPS,
		CS_MODE_64 + CS_MODE_LITTLE_ENDIAN,
		MIPS_CODE2,
		"MIPS-64-EL (Little-endian)",
	},
}

var x86_tests = platforms{
	platform{
		CS_ARCH_X86,
		CS_MODE_16,
		X86_CODE16,
		"X86 16bit (Intel syntax)",
	},
	platform{
		CS_ARCH_X86,
		CS_MODE_32 + CS_MODE_SYNTAX_ATT,
		X86_CODE32,
		"X86 32 (AT&T syntax)",
	},
	platform{
		CS_ARCH_X86,
		CS_MODE_32,
		X86_CODE32,
		"X86 32 (Intel syntax)",
	},
	platform{
		CS_ARCH_X86,
		CS_MODE_64,
		X86_CODE64,
		"X86 64 (Intel syntax)",
	},
}

func dumpHex(code []byte, buf *bytes.Buffer) {
	for _, b := range code {
		fmt.Fprintf(buf, "0x%.2x ", b)
	}
	fmt.Fprintf(buf, "\n")
}
