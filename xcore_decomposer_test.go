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

func xcoreInsnDetail(insn Instruction, engine *Engine, buf *bytes.Buffer) {

	if len(insn.Xcore.Operands) > 0 {
		fmt.Fprintf(buf, "\top_count: %v\n", len(insn.Xcore.Operands))
	}

	for i, op := range insn.Xcore.Operands {
		switch op.Type {
		case XCORE_OP_REG:
			fmt.Fprintf(buf, "\t\toperands[%v].type: REG = %v\n", i, engine.RegName(op.Reg))
		case XCORE_OP_IMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = 0x%x\n", i, (uint64(op.Imm)))
		case XCORE_OP_MEM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: MEM\n", i)
			if op.Mem.Base != XCORE_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.base: REG = %s\n",
					i, engine.RegName(uint(op.Mem.Base)))
			}
			if op.Mem.Index != XCORE_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.index: REG = %s\n",
					i, engine.RegName(uint(op.Mem.Index)))
			}
			if op.Mem.Disp != 0 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.disp: 0x%x\n", i, uint64(op.Mem.Disp))
			}
			// wacky logic, rite? It's from the C test.
			if op.Mem.Direct != 1 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.direct: -1\n", i)
			}
		}

	}

	fmt.Fprintf(buf, "\n")
}

func TestXcore(t *testing.T) {

	t.Parallel()

	final := new(bytes.Buffer)
	spec_file := "xcore.SPEC"

	for i, platform := range xcoreTests {

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
			t.Logf("Arch: Xcore. Capstone Version: %v.%v", maj, min)
			check := checks[CS_ARCH_XCORE]
			if check.grpMax != XCORE_GRP_ENDING ||
				check.insMax != XCORE_INS_ENDING ||
				check.regMax != XCORE_REG_ENDING {
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
				xcoreInsnDetail(insn, &engine, final)
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
