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

var arm64_tests = platforms{
	platform{
		CS_ARCH_ARM64,
		CS_MODE_ARM,
		ARM64_CODE,
		"ARM-64",
	},
}

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

func dumpCode(code string, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "Code:")
	for _, b := range []byte(code) {
		fmt.Fprintf(buf, "0x%.2x ", b)
	}
	fmt.Fprintf(buf, "\n")
}
