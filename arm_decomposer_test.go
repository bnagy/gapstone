package gapstone

import "testing"
import "bytes"
import "fmt"
import "io/ioutil"

//import "encoding/hex"

type platform struct {
	arch    Arch
	mode    Mode
	code    string
	comment string
}
type platforms []platform

const ARM_CODE = "\xED\xFF\xFF\xEB\x04\xe0\x2d\xe5\x00\x00\x00\x00\xe0\x83\x22\xe5\xf1\x02\x03\x0e\x00\x00\xa0\xe3\x02\x30\xc1\xe7\x00\x00\x53\xe3"
const ARM_CODE2 = "\xd1\xe8\x00\xf0\xf0\x24\x04\x07\x1f\x3c\xf2\xc0\x00\x00\x4f\xf0\x00\x01\x46\x6c"
const THUMB_CODE = "\x70\x47\xeb\x46\x83\xb0\xc9\x68\x1f\xb1"
const THUMB_CODE2 = "\x4f\xf0\x00\x01\xbd\xe8\x00\x88\xd1\xe8\x00\xf0"

const OFFSET = 0x1000
const SPEC = "arm.SPEC"

var tests = platforms{
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

func dumpCode(code string) *bytes.Buffer {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "Code:")
	for _, b := range []byte(code) {
		fmt.Fprintf(buf, "%.2x ", b)
	}
	fmt.Fprintf(buf, "\n")
	return buf
}

func insnDetail(insn Instruction, engine *Engine) *bytes.Buffer {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "\top_count: %v\n", len(insn.Arm.Operands))
	for i, op := range insn.Arm.Operands {

		switch op.Type {
		case ARM_OP_REG:
			fmt.Fprintf(buf, "\t\toperands[%v].type: REG = %v\n", i, engine.RegName(op.Reg))
		case ARM_OP_IMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = 0x%x\n", i, op.Imm)
		case ARM_OP_FP:
			fmt.Fprintf(buf, "\t\toperands[%v].type: FP = %f\n", i, op.FP)
		case ARM_OP_MEM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: MEM\n", i)
			if op.Mem.Base != ARM_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.base: REG = %s\n",
					i, engine.RegName(op.Mem.Base))
			}
			if op.Mem.Index != ARM_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.index: REG = %s\n",
					i, engine.RegName(op.Mem.Index))
			}
			if op.Mem.Scale != 1 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.scale: %v\n", i, op.Mem.Scale)
			}
			if op.Mem.Disp != 0 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.disp: 0x%x\n", i, op.Mem.Disp)
			}
		case ARM_OP_PIMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: P-IMM = %v\n", i, op.Imm)
		case ARM_OP_CIMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: C-IMM = %v\n", i, op.Imm)
		}

		if op.Shift.Type != ARM_SFT_INVALID && op.Shift.Value != 0 {
			if op.Shift.Type < ARM_SFT_ASR_REG {
				// shift with constant value
				fmt.Fprintf(buf, "\t\t\tShift: %v = %v\n", op.Shift.Type, op.Shift.Value)
			} else {
				// shift with register
				fmt.Fprintf(buf, "\t\t\tShift: %v = %s\n", op.Shift.Type, engine.RegName(op.Shift.Value))
			}
		}

	}

	if insn.Arm.CC != ARM_CC_AL && insn.Arm.CC != ARM_CC_INVALID {
		fmt.Fprintf(buf, "\tCode condition: %v\n", insn.Arm.CC)
	}
	if insn.Arm.UpdateFlags {
		fmt.Fprintf(buf, "\tUpdate-flags: True\n")
	}
	if insn.Arm.Writeback {
		fmt.Fprintf(buf, "\tWrite-back: True\n")
	}

	fmt.Fprintf(buf, "\n")
	return buf
}

func TestBasic(t *testing.T) {
	final := new(bytes.Buffer)
	for _, platform := range tests {

		engine, err := New(platform.arch, platform.mode)
		if err != nil {
			fmt.Println(err)
			return
		}
		defer engine.Close()
		if insns, err := engine.Disasm(platform.code, OFFSET, 0); err == nil {
			fmt.Fprintf(final, "****************\n")
			fmt.Fprintf(final, "Platform: %s\n", platform.comment)
			fmt.Fprint(final, dumpCode(platform.code).String())
			fmt.Fprintf(final, "Disasm:\n")
			for _, insn := range insns {
				fmt.Fprintf(final, "0x%x:\t%s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
				fmt.Fprint(final, insnDetail(insn, &engine).String())
			}
			fmt.Fprintf(final, "0x%x:\n", insns[len(insns)-1].Address+insns[len(insns)-1].Size)
		}
	}
	spec, err := ioutil.ReadFile(SPEC)
	if err != nil {
		fmt.Errorf("Cannot read spec file %v: %v", SPEC, err)
	}
	if string(spec) != final.String() {
		fmt.Errorf("Output failed to match spec!")
	}
}
