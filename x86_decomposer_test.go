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

func x86InsnDetail(insn Instruction, engine *Engine, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "\tPrefix:")
	dumpHex(insn.X86.Prefix, buf)

	fmt.Fprintf(buf, "\tOpcode:")
	dumpHex(insn.X86.Opcode, buf)

	fmt.Fprintf(buf, "\trex: 0x%x\n", insn.X86.Rex)
	fmt.Fprintf(buf, "\taddr_size: %v\n", insn.X86.AddrSize)
	fmt.Fprintf(buf, "\tmodrm: 0x%x\n", insn.X86.ModRM)
	fmt.Fprintf(buf, "\tdisp: 0x%x\n", uint32(insn.X86.Disp))

	// SIB is not available in 16-bit mode
	if (engine.Mode() & CS_MODE_16) == 0 {
		fmt.Fprintf(buf, "\tsib: 0x%x\n", insn.X86.Sib)
		if insn.X86.SibIndex != X86_REG_INVALID {
			fmt.Fprintf(
				buf,
				"\t\tsib_base: %s\n\t\tsib_index: %s\n\t\tsib_scale: %v\n",
				engine.RegName(insn.X86.SibBase),
				engine.RegName(insn.X86.SibIndex),
				insn.X86.SibScale,
			)
		}
	}
	// SSE code condition
	if insn.X86.SseCC != X86_SSE_CC_INVALID {
		fmt.Fprintf(buf, "\tsse_cc: %v\n", insn.X86.SseCC)
	}

	// AVX code condition
	if insn.X86.AvxCC != X86_AVX_CC_INVALID {
		fmt.Fprintf(buf, "\tavx_cc: %v\n", insn.X86.AvxCC)
	}

	// AVX Suppress All Exception
	if insn.X86.AvxSAE {
		fmt.Fprintf(buf, "\tavx_sae: %v\n", insn.X86.AvxSAE)
	}

	// AVX Rounding Mode
	if insn.X86.AvxRM != X86_AVX_RM_INVALID {
		fmt.Fprintf(buf, "\tavx_rm: %v\n", insn.X86.AvxRM)
	}

	if immcount := insn.X86.OpCount(X86_OP_IMM); immcount > 0 {
		fmt.Fprintf(buf, "\timm_count: %v\n", immcount)
		pos := 1
		for _, op := range insn.X86.Operands {
			if op.Type == X86_OP_IMM {
				fmt.Fprintf(
					buf,
					"\t\timms[%v]: 0x%x\n", pos, uint64(op.Imm),
				)
				pos++
			}
		}
	}

	if oplen := len(insn.X86.Operands); oplen > 0 {
		fmt.Fprintf(buf, "\top_count: %v\n", oplen)
	}

	for i, op := range insn.X86.Operands {
		switch op.Type {
		case X86_OP_REG:
			fmt.Fprintf(buf, "\t\toperands[%v].type: REG = %v\n", i, engine.RegName(op.Reg))
		case X86_OP_IMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = 0x%x\n", i, (uint64(op.Imm)))
		case X86_OP_FP:
			fmt.Fprintf(buf, "\t\toperands[%v].type: FP = %f\n", i, op.FP)
		case X86_OP_MEM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: MEM\n", i)
			if op.Mem.Segment != X86_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.segment: REG = %s\n", i, engine.RegName(op.Mem.Segment))
			}
			if op.Mem.Base != X86_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.base: REG = %s\n",
					i, engine.RegName(op.Mem.Base))
			}
			if op.Mem.Index != X86_REG_INVALID {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.index: REG = %s\n",
					i, engine.RegName(op.Mem.Index))
			}
			if op.Mem.Scale != 1 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.scale: %v\n", i, op.Mem.Scale)
			}
			if op.Mem.Disp != 0 {
				fmt.Fprintf(buf, "\t\t\toperands[%v].mem.disp: 0x%x\n", i, uint64(op.Mem.Disp))
			}
		}

		// AVX broadcast type
		if op.AvxBcast != X86_AVX_BCAST_INVALID {
			fmt.Fprintf(buf, "\t\toperands[%v].avx_bcast: %v\n", i, op.AvxBcast)
		}

		// AVX zero opmask {z}
		if op.AvxZeroOpmask {
			fmt.Fprintf(buf, "\t\toperands[%v].avx_zero_opmask: TRUE\n", i)
		}

		fmt.Fprintf(buf, "\t\toperands[%v].size: %v\n", i, op.Size)

	}

	fmt.Fprintf(buf, "\n")
}

func TestX86(t *testing.T) {

	t.Parallel()

	final := new(bytes.Buffer)
	spec_file := "x86.SPEC"

	for i, platform := range x86Tests {

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
			t.Logf("Arch: x86. Capstone Version: %v.%v", maj, min)
			check := checks[CS_ARCH_X86]
			if check.grpMax != X86_GRP_ENDING ||
				check.insMax != X86_INS_ENDING ||
				check.regMax != X86_REG_ENDING {
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
				x86InsnDetail(insn, &engine, final)
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
