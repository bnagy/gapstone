/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

	Library Author: Nguyen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details
    (c) 2013 COSEINC. All Rights Reserved.
*/

package gapstone

import "testing"
import "bytes"
import "fmt"
import "io/ioutil"

func arm64InsnDetail(insn Instruction, engine *Engine, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "\top_count: %v\n", len(insn.Arm64.Operands))

	for i, op := range insn.Arm64.Operands {
		switch op.Type {
		case ARM64_OP_REG:
			fmt.Fprintf(buf, "\t\toperands[%v].type: REG = %v\n", i, engine.RegName(op.Reg))
		case ARM64_OP_IMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = 0x%x\n", i, (uint64(op.Imm)))
		case ARM64_OP_FP:
			fmt.Fprintf(buf, "\t\toperands[%v].type: FP = %f\n", i, op.FP)
		case ARM64_OP_MEM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: MEM\n", i)
			if op.Mem.Base != ARM64_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.base: REG = %s\n",
					i, engine.RegName(op.Mem.Base))
			}
			if op.Mem.Index != ARM64_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.index: REG = %s\n",
					i, engine.RegName(op.Mem.Index))
			}
			if op.Mem.Disp != 0 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.disp: 0x%x\n", i, uint64(op.Mem.Disp))
			}
		case ARM64_OP_CIMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: C-IMM = %v\n", i, op.Imm)
		}

		if op.Shift.Type != ARM64_SFT_INVALID && op.Shift.Value != 0 {
			// shift with constant value
			fmt.Fprintf(buf, "\t\t\tShift: type = %v, value = %v\n", op.Shift.Type, op.Shift.Value)
		}
		if op.Ext != ARM64_EXT_INVALID {
			fmt.Fprintf(buf, "\t\t\tExt: %v\n", op.Ext)
		}

	}

	if insn.Arm64.CC != ARM64_CC_AL && insn.Arm64.CC != ARM64_CC_INVALID {
		fmt.Fprintf(buf, "\tCode condition: %v\n", insn.Arm64.CC)
	}
	if insn.Arm64.UpdateFlags {
		fmt.Fprintf(buf, "\tUpdate-flags: True\n")
	}
	if insn.Arm64.Writeback {
		fmt.Fprintf(buf, "\tWrite-back: True\n")
	}

	fmt.Fprintf(buf, "\n")
}

func TestArm64(t *testing.T) {

	t.Parallel()

	final := new(bytes.Buffer)
	spec_file := "arm64.SPEC"

	for i, platform := range arm64Tests {

		engine, err := New(platform.arch, platform.mode)
		if err != nil {
			t.Errorf("Failed to initialize engine %v", err)
			return
		}
		for _, opt := range platform.options {
			engine.SetOption(opt.ty, opt.value)
		}
		if i == 0 {
			maj, min := engine.Version()
			t.Logf("Arch: Arm64. Capstone Version: %v.%v", maj, min)
			check := checks[CS_ARCH_ARM64]
			if check.grpMax != ARM64_GRP_MAX ||
				check.insMax != ARM64_INS_MAX ||
				check.regMax != ARM64_REG_MAX {
				t.Errorf("Failed in sanity check. Constants out of sync with core.")
			} else {
				t.Logf("Sanity Check: PASS")
			}
		}
		defer engine.Close()

		insns, err := engine.Disasm([]byte(platform.code), 0x2c, 0)
		if err == nil {
			fmt.Fprintf(final, "****************\n")
			fmt.Fprintf(final, "Platform: %s\n", platform.comment)
			fmt.Fprintf(final, "Code:")
			dumpHex([]byte(platform.code), final)
			fmt.Fprintf(final, "Disasm:\n")
			for _, insn := range insns {
				fmt.Fprintf(final, "0x%x:\t%s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
				arm64InsnDetail(insn, &engine, final)
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
		//fmt.Println(fs)
		t.Errorf("Output failed to match spec!")
	} else {
		t.Logf("Clean diff with %v.\n", spec_file)
	}

}
