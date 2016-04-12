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

// TODO - WTF is this doing lying about in test code?
var addressingModes = []string{
	"<invalid mode>",
	"Register Direct - Data",
	"Register Direct - Address",
	"Register Indirect - Address",
	"Register Indirect - Address with Postincrement",
	"Register Indirect - Address with Predecrement",
	"Register Indirect - Address with Displacement",
	"Address Register Indirect With Index - 8-bit displacement",
	"Address Register Indirect With Index - Base displacement",
	"Memory indirect - Postindex",
	"Memory indirect - Preindex",
	"Program Counter Indirect - with Displacement",
	"Program Counter Indirect with Index - with 8-Bit Displacement",
	"Program Counter Indirect with Index - with Base Displacement",
	"Program Counter Memory Indirect - Postindexed",
	"Program Counter Memory Indirect - Preindexed",
	"Absolute Data Addressing  - Short",
	"Absolute Data Addressing  - Long",
	"Immidate value",
}

func m68kInsnDetail(insn Instruction, engine *Engine, buf *bytes.Buffer) error {

	if len(insn.M68k.Operands) > 0 {
		fmt.Fprintf(buf, "\top_count: %v\n", len(insn.M68k.Operands))
	}

	for i, op := range insn.M68k.Operands {
		switch op.Type {
		default:
			return fmt.Errorf("unknown op.Type %v", op.Type)

		case M68K_OP_REG:
			fmt.Fprintf(buf, "\t\toperands[%v].type: REG = %v\n", i, engine.RegName(op.Reg))

		case M68K_OP_IMM:
			switch insn.M68k.OpSizeType {
			default:
				fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = <unsupported>\n", i)

			case M68K_SIZE_TYPE_FPU:
				switch insn.M68k.OpSize {
				default:
					fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = <unsupported>\n", i)

				case M68K_FPU_SIZE_SINGLE:
					fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = %f\n", i, op.Simm)

				case M68K_FPU_SIZE_DOUBLE:
					fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = %f\n", i, op.Dimm)
				}

			case M68K_SIZE_TYPE_CPU:
				fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = 0x%x\n", i, op.Imm&0xffffffff)
			}

		case M68K_OP_MEM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: MEM\n", i)
			if op.Mem.BaseReg != M68K_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.base: REG = %s\n",
					i, engine.RegName(op.Mem.BaseReg))
			}
			if op.Mem.IndexReg != M68K_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.index: REG = %s\n",
					i, engine.RegName(op.Mem.IndexReg))
				if op.Mem.IndexSize > 0 {
					fmt.Fprintf(buf, "\t\t\toperands[%v].mem.index: size = l\n", i)
				} else {
					fmt.Fprintf(buf, "\t\t\toperands[%v].mem.index: size = w\n", i)
				}
			}
			if op.Mem.Disp != 0 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.disp: 0x%x\n", i, uint64(op.Mem.Disp))
			}
			if op.Mem.Scale != 0 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.scale: %v\n", i, op.Mem.Scale)
			}
			fmt.Fprintf(buf, "\t\taddress mode: %s\n", addressingModes[op.AddressMode])
		}

	}

	fmt.Fprintf(buf, "\n")
	return nil
}

func TestM68k(t *testing.T) {

	t.Parallel()

	final := new(bytes.Buffer)
	specFile := "m68k.SPEC"

	for i, platform := range m68kTests {

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
			t.Logf("Arch: M68k. Capstone Version: %v.%v", maj, min)
			check := checks[CS_ARCH_M68K]
			if check.grpMax != M68K_GRP_ENDING ||
				check.insMax != M68K_INS_ENDING ||
				check.regMax != M68K_REG_ENDING {
				t.Errorf("Constants out of sync with core! (did you re-run genconst?)")
			} else {
				t.Logf("Sanity Check: PASS")
			}
		}
		defer engine.Close()

		insns, err := engine.Disasm([]byte(platform.code), address, 0)
		if err == nil {
			fmt.Fprintf(final, "****************\n")
			fmt.Fprintf(final, "Platform: %s\n", platform.comment)
			fmt.Fprintf(final, "Code: ")
			dumpHex([]byte(platform.code), final)
			fmt.Fprintf(final, "Disasm:\n")
			for _, insn := range insns {
				fmt.Fprintf(final, "0x%x:\t%s\t%s\n", insn.Address, insn.Mnemonic, insn.OpStr)
				err := m68kInsnDetail(insn, &engine, final)
				if err != nil {
					t.Fatalf("m68kInsnDetail: %s", err)
				}
			}
			fmt.Fprintf(final, "0x%x:\n", insns[len(insns)-1].Address+insns[len(insns)-1].Size)
			fmt.Fprintf(final, "\n")
		} else {
			t.Errorf("Disassembly error: %v\n", err)
		}

	}

	spec, err := ioutil.ReadFile(specFile)
	if err != nil {
		t.Errorf("Cannot read spec file %v: %v", specFile, err)
	}
	if fs := final.String(); string(spec) != fs {
		// fmt.Println(fs)
		t.Errorf("Output failed to match spec! (did you re-run genspec?)")
	} else {
		t.Logf("Clean diff with %v.\n", specFile)
	}

}
