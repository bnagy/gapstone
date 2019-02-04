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
	"bytes"
	"fmt"
	"io/ioutil"
	"testing"
)

func armInsnDetail(insn Instruction, engine *Engine, buf *bytes.Buffer) {
	if oplen := len(insn.Arm.Operands); oplen > 0 {
		fmt.Fprintf(buf, "\top_count: %v\n", oplen)
	}

	for i, op := range insn.Arm.Operands {
		switch op.Type {
		case ARM_OP_REG:
			fmt.Fprintf(buf, "\t\toperands[%v].type: REG = %v\n", i, engine.RegName(op.Reg))
		case ARM_OP_IMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = 0x%x\n", i, (uint32(op.Imm)))
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
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.disp: 0x%x\n", i, uint32(op.Mem.Disp))
			}
			if op.Mem.LShift != 0 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.lshift: 0x%x\n", i, uint32(op.Mem.LShift))
			}
		case ARM_OP_PIMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: P-IMM = %v\n", i, op.Imm)
		case ARM_OP_CIMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: C-IMM = %v\n", i, op.Imm)
		case ARM_OP_SETEND:
			if op.Setend == ARM_SETEND_BE {
				fmt.Fprintf(buf, "\t\toperands[%v].type: SETEND = be\n", i)
			} else {
				fmt.Fprintf(buf, "\t\toperands[%v].type: SETEND = le\n", i)
			}
		case ARM_OP_SYSREG:
			fmt.Fprintf(buf, "\t\toperands[%v].type: SYSREG = %v\n", i, op.Reg)

		}

		if op.NeonLane != -1 {
			fmt.Fprintf(buf, "\t\toperands[%v].neon_lane = %v\n", i, op.NeonLane)
		}

		switch op.Access {
		case CS_AC_READ:
			fmt.Fprintf(buf, "\t\toperands[%v].access: READ\n", i)
		case CS_AC_WRITE:
			fmt.Fprintf(buf, "\t\toperands[%v].access: WRITE\n", i)
		case CS_AC_READ | CS_AC_WRITE:
			fmt.Fprintf(buf, "\t\toperands[%v].access: READ | WRITE\n", i)
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

		if op.VectorIndex != -1 {
			fmt.Fprintf(buf, "\t\toperands[%v].vector_index = %v\n", i, op.VectorIndex)
		}

		if op.Subtracted {
			fmt.Fprintf(buf, "\t\tSubtracted: True\n")
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

	if insn.Arm.CPSMode != 0 {
		fmt.Fprintf(buf, "\tCPSI-mode: %v\n", insn.Arm.CPSMode)
	}

	if insn.Arm.CPSFlag != 0 {
		fmt.Fprintf(buf, "\tCPSI-flag: %v\n", insn.Arm.CPSFlag)
	}

	if insn.Arm.VectorData != 0 {
		fmt.Fprintf(buf, "\tVector-data: %v\n", insn.Arm.VectorData)
	}

	if insn.Arm.VectorSize != 0 {
		fmt.Fprintf(buf, "\tVector-size: %v\n", insn.Arm.VectorSize)
	}

	if insn.Arm.UserMode {
		fmt.Fprintf(buf, "\tUser-mode: True\n")
	}

	if insn.Arm.MemBarrier != 0 {
		fmt.Fprintf(buf, "\tMemory-barrier: %v\n", insn.Arm.MemBarrier)
	}

	if len(insn.AllRegistersRead) > 0 {
		fmt.Fprintf(buf, "\tRegisters read:")
		for _, reg := range insn.AllRegistersRead {
			fmt.Fprintf(buf, " %s", engine.RegName(reg))
		}
		fmt.Fprintf(buf, "\n")
	}

	if len(insn.AllRegistersWritten) > 0 {
		fmt.Fprintf(buf, "\tRegisters modified:")
		for _, reg := range insn.AllRegistersWritten {
			fmt.Fprintf(buf, " %s", engine.RegName(reg))
		}
		fmt.Fprintf(buf, "\n")
	}

	fmt.Fprintf(buf, "\n")
}

func TestArm(t *testing.T) {

	t.Parallel()

	var address = uint64(0x80001000)
	final := new(bytes.Buffer)
	spec_file := "arm.SPEC"

	for i, platform := range armTests {

		engine, err := New(platform.arch, platform.mode)
		if err != nil {
			t.Errorf("Failed to initialize engine %v", err.Error())
			return
		}
		for _, opt := range platform.options {
			engine.SetOption(opt.ty, opt.value)
		}
		if i == 0 {
			maj, min := engine.Version()
			t.Logf("Arch: Arm. Capstone Version: %v.%v", maj, min)
			check := checks[CS_ARCH_ARM]
			if check.grpMax != ARM_GRP_ENDING ||
				check.insMax != ARM_INS_ENDING ||
				check.regMax != ARM_REG_ENDING {
				t.Errorf("Failed in sanity check. Constants out of sync with core.")
			} else {
				t.Logf("Sanity Check: PASS")
			}
		}
		defer engine.Close()

		if insns, err := engine.Disasm([]byte(platform.code), address, 0); err == nil {
			fmt.Fprintf(final, "****************\n")
			fmt.Fprintf(final, "Platform: %s\n", platform.comment)
			fmt.Fprintf(final, "Code:")
			dumpHex([]byte(platform.code), final)
			fmt.Fprintf(final, "Disasm:\n")
			for _, insn := range insns {
				fmt.Fprintf(final, "0x%x:\t%s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
				armInsnDetail(insn, &engine, final)
			}
			fmt.Fprintf(final, "0x%x:\n\n", insns[len(insns)-1].Address+insns[len(insns)-1].Size)
		}
	}

	spec, err := ioutil.ReadFile(spec_file)
	if err != nil {
		t.Errorf("Cannot read spec file %v: %v", spec_file, err)
	}
	if fs := final.String(); string(spec) != fs {
		// fmt.Println(fs)
		t.Errorf("Output failed to match spec!")
	} else {
		t.Logf("Clean diff with %v.\n", spec_file)
	}
}
