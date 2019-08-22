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

func getBCName(bc uint) string {
	switch bc {
	default:
		return ""
	case PPC_BC_INVALID:
		return "invalid"
	case PPC_BC_LT:
		return "lt"
	case PPC_BC_LE:
		return "le"
	case PPC_BC_EQ:
		return "eq"
	case PPC_BC_GE:
		return "ge"
	case PPC_BC_GT:
		return "gt"
	case PPC_BC_NE:
		return "ne"
	case PPC_BC_UN:
		return "un"
	case PPC_BC_NU:
		return "nu"
	case PPC_BC_SO:
		return "so"
	case PPC_BC_NS:
		return "ns"
	}
}
func ppcInsnDetail(insn Instruction, engine *Engine, buf *bytes.Buffer) {

	if len(insn.PPC.Operands) > 0 {
		fmt.Fprintf(buf, "\top_count: %v\n", len(insn.PPC.Operands))
	}
	for i, op := range insn.PPC.Operands {
		switch op.Type {
		case PPC_OP_REG:
			fmt.Fprintf(buf, "\t\toperands[%v].type: REG = %v\n", i, engine.RegName(op.Reg))
		case PPC_OP_IMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = 0x%x\n", i, uint64(op.Imm))
		case PPC_OP_MEM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: MEM\n", i)
			if op.Mem.Base != PPC_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.base: REG = %s\n",
					i, engine.RegName(op.Mem.Base))
			}
			if op.Mem.Disp != 0 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.disp: 0x%x\n", i, uint64(op.Mem.Disp))
			}
		case PPC_OP_CRX:
			fmt.Fprintf(buf, "\t\toperands[%v].type: CRX\n", i)
			fmt.Fprintf(buf, "\t\t\toperands[%v].crx.scale: %d\n", i, uint(op.CRX.Scale))
			fmt.Fprintf(buf, "\t\t\toperands[%v].crx.reg: %s\n", i, engine.RegName(op.CRX.Reg))
			fmt.Fprintf(buf, "\t\t\toperands[%v].crx.cond: %s\n", i, getBCName(op.CRX.Cond))
		}

	}

	if insn.PPC.BC != 0 {
		fmt.Fprintf(buf, "\tBranch code: %v\n", insn.PPC.BC)
	}

	if insn.PPC.BH != 0 {
		fmt.Fprintf(buf, "\tBranch hint: %v\n", insn.PPC.BH)
	}

	if insn.PPC.UpdateCR0 {
		fmt.Fprintf(buf, "\tUpdate-CR0: True\n")
	}

	fmt.Fprintf(buf, "\n")
}

func TestPPC(t *testing.T) {

	t.Parallel()

	final := new(bytes.Buffer)
	spec_file := "ppc.SPEC"

	for i, platform := range ppcTests {

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
			t.Logf("Arch: PPC. Capstone Version: %v.%v", maj, min)
			check := checks[CS_ARCH_PPC]
			if check.grpMax != PPC_GRP_ENDING ||
				check.insMax != PPC_INS_ENDING ||
				check.regMax != PPC_REG_ENDING {
				t.Errorf("Failed in sanity check. Constants out of sync with core.")
			} else {
				t.Logf("Sanity Check: PASS")
			}
		}
		defer engine.Close()

		insns, err := engine.Disasm([]byte(platform.code), address, 0)
		if err == nil {
			fmt.Fprintf(final, "****************\n")
			fmt.Fprintf(final, "Platform: %s\n", platform.comment)
			fmt.Fprintf(final, "Code:")
			dumpHex([]byte(platform.code), final)
			fmt.Fprintf(final, "Disasm:\n")
			for _, insn := range insns {
				fmt.Fprintf(final, "0x%x:\t%s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
				ppcInsnDetail(insn, &engine, final)
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
		// fmt.Println(fs)
		t.Errorf("Output failed to match spec!")
	} else {
		t.Logf("Clean diff with %v.\n", spec_file)
	}

}
