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

func getEFlagName(flag uint64) string {
	switch flag {
	default:
		return ""
	case X86_EFLAGS_UNDEFINED_OF:
		return "UNDEF_OF"
	case X86_EFLAGS_UNDEFINED_SF:
		return "UNDEF_SF"
	case X86_EFLAGS_UNDEFINED_ZF:
		return "UNDEF_ZF"
	case X86_EFLAGS_MODIFY_AF:
		return "MOD_AF"
	case X86_EFLAGS_UNDEFINED_PF:
		return "UNDEF_PF"
	case X86_EFLAGS_MODIFY_CF:
		return "MOD_CF"
	case X86_EFLAGS_MODIFY_SF:
		return "MOD_SF"
	case X86_EFLAGS_MODIFY_ZF:
		return "MOD_ZF"
	case X86_EFLAGS_UNDEFINED_AF:
		return "UNDEF_AF"
	case X86_EFLAGS_MODIFY_PF:
		return "MOD_PF"
	case X86_EFLAGS_UNDEFINED_CF:
		return "UNDEF_CF"
	case X86_EFLAGS_MODIFY_OF:
		return "MOD_OF"
	case X86_EFLAGS_RESET_OF:
		return "RESET_OF"
	case X86_EFLAGS_RESET_CF:
		return "RESET_CF"
	case X86_EFLAGS_RESET_DF:
		return "RESET_DF"
	case X86_EFLAGS_RESET_IF:
		return "RESET_IF"
	case X86_EFLAGS_TEST_OF:
		return "TEST_OF"
	case X86_EFLAGS_TEST_SF:
		return "TEST_SF"
	case X86_EFLAGS_TEST_ZF:
		return "TEST_ZF"
	case X86_EFLAGS_TEST_PF:
		return "TEST_PF"
	case X86_EFLAGS_TEST_CF:
		return "TEST_CF"
	case X86_EFLAGS_RESET_SF:
		return "RESET_SF"
	case X86_EFLAGS_RESET_AF:
		return "RESET_AF"
	case X86_EFLAGS_RESET_TF:
		return "RESET_TF"
	case X86_EFLAGS_RESET_NT:
		return "RESET_NT"
	case X86_EFLAGS_PRIOR_OF:
		return "PRIOR_OF"
	case X86_EFLAGS_PRIOR_SF:
		return "PRIOR_SF"
	case X86_EFLAGS_PRIOR_ZF:
		return "PRIOR_ZF"
	case X86_EFLAGS_PRIOR_AF:
		return "PRIOR_AF"
	case X86_EFLAGS_PRIOR_PF:
		return "PRIOR_PF"
	case X86_EFLAGS_PRIOR_CF:
		return "PRIOR_CF"
	case X86_EFLAGS_PRIOR_TF:
		return "PRIOR_TF"
	case X86_EFLAGS_PRIOR_IF:
		return "PRIOR_IF"
	case X86_EFLAGS_PRIOR_DF:
		return "PRIOR_DF"
	case X86_EFLAGS_TEST_NT:
		return "TEST_NT"
	case X86_EFLAGS_TEST_DF:
		return "TEST_DF"
	case X86_EFLAGS_RESET_PF:
		return "RESET_PF"
	case X86_EFLAGS_PRIOR_NT:
		return "PRIOR_NT"
	case X86_EFLAGS_MODIFY_TF:
		return "MOD_TF"
	case X86_EFLAGS_MODIFY_IF:
		return "MOD_IF"
	case X86_EFLAGS_MODIFY_DF:
		return "MOD_DF"
	case X86_EFLAGS_MODIFY_NT:
		return "MOD_NT"
	case X86_EFLAGS_MODIFY_RF:
		return "MOD_RF"
	case X86_EFLAGS_SET_CF:
		return "SET_CF"
	case X86_EFLAGS_SET_DF:
		return "SET_DF"
	case X86_EFLAGS_SET_IF:
		return "SET_IF"
	}
}

func getFPUFlagName(flag uint64) string {
	switch flag {
	default:
		return ""
	case X86_FPU_FLAGS_MODIFY_C0:
		return "MOD_C0"
	case X86_FPU_FLAGS_MODIFY_C1:
		return "MOD_C1"
	case X86_FPU_FLAGS_MODIFY_C2:
		return "MOD_C2"
	case X86_FPU_FLAGS_MODIFY_C3:
		return "MOD_C3"
	case X86_FPU_FLAGS_RESET_C0:
		return "RESET_C0"
	case X86_FPU_FLAGS_RESET_C1:
		return "RESET_C1"
	case X86_FPU_FLAGS_RESET_C2:
		return "RESET_C2"
	case X86_FPU_FLAGS_RESET_C3:
		return "RESET_C3"
	case X86_FPU_FLAGS_SET_C0:
		return "SET_C0"
	case X86_FPU_FLAGS_SET_C1:
		return "SET_C1"
	case X86_FPU_FLAGS_SET_C2:
		return "SET_C2"
	case X86_FPU_FLAGS_SET_C3:
		return "SET_C3"
	case X86_FPU_FLAGS_UNDEFINED_C0:
		return "UNDEF_C0"
	case X86_FPU_FLAGS_UNDEFINED_C1:
		return "UNDEF_C1"
	case X86_FPU_FLAGS_UNDEFINED_C2:
		return "UNDEF_C2"
	case X86_FPU_FLAGS_UNDEFINED_C3:
		return "UNDEF_C3"
	case X86_FPU_FLAGS_TEST_C0:
		return "TEST_C0"
	case X86_FPU_FLAGS_TEST_C1:
		return "TEST_C1"
	case X86_FPU_FLAGS_TEST_C2:
		return "TEST_C2"
	case X86_FPU_FLAGS_TEST_C3:
		return "TEST_C3"
	}
}

func x86InsnDetail(insn Instruction, engine *Engine, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "\tPrefix:")
	dumpHex(insn.X86.Prefix, buf)

	fmt.Fprintf(buf, "\tOpcode:")
	dumpHex(insn.X86.Opcode, buf)

	fmt.Fprintf(buf, "\trex: 0x%x\n", insn.X86.Rex)
	fmt.Fprintf(buf, "\taddr_size: %v\n", insn.X86.AddrSize)
	fmt.Fprintf(buf, "\tmodrm: 0x%x\n", insn.X86.ModRM)
	if insn.X86.Encoding.ModRMOffset != 0 {
		fmt.Fprintf(buf, "\tmodrm_offset: 0x%x\n", insn.X86.Encoding.ModRMOffset)
	}

	fmt.Fprintf(buf, "\tdisp: 0x%x\n", uint64(insn.X86.Disp))
	if insn.X86.Encoding.DispOffset != 0 {
		fmt.Fprintf(buf, "\tdisp_offset: 0x%x\n", insn.X86.Encoding.DispOffset)
	}

	if insn.X86.Encoding.DispSize != 0 {
		fmt.Fprintf(buf, "\tdisp_size: 0x%x\n", insn.X86.Encoding.DispSize)
	}

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

	// XOP code condition
	if insn.X86.XopCC != X86_XOP_CC_INVALID {
		fmt.Fprintf(buf, "\txop_cc: %v\n", insn.X86.XopCC)
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

	// Print out all immediate operands
	if immcount := insn.X86.OpCount(X86_OP_IMM); immcount > 0 {
		fmt.Fprintf(buf, "\timm_count: %v\n", immcount)
		pos := 1
		for _, op := range insn.X86.Operands {
			if op.Type == X86_OP_IMM {
				fmt.Fprintf(buf, "\t\timms[%v]: 0x%x\n", pos, uint64(op.Imm))
				if insn.X86.Encoding.ImmOffset != 0 {
					fmt.Fprintf(buf, "\timm_offset: 0x%x\n", insn.X86.Encoding.ImmOffset)
				}

				if insn.X86.Encoding.ImmSize != 0 {
					fmt.Fprintf(buf, "\timm_size: 0x%x\n", insn.X86.Encoding.ImmSize)
				}
				pos++
			}
		}
	}

	if oplen := len(insn.X86.Operands); oplen > 0 {
		fmt.Fprintf(buf, "\top_count: %v\n", oplen)
	}

	// Print out all operands
	for i, op := range insn.X86.Operands {
		switch op.Type {
		case X86_OP_REG:
			fmt.Fprintf(buf, "\t\toperands[%v].type: REG = %v\n", i, engine.RegName(op.Reg))
		case X86_OP_IMM:
			fmt.Fprintf(buf, "\t\toperands[%v].type: IMM = 0x%x\n", i, (uint64(op.Imm)))
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

		switch op.Access {
		case CS_AC_READ:
			fmt.Fprintf(buf, "\t\toperands[%v].access: READ\n", i)
		case CS_AC_WRITE:
			fmt.Fprintf(buf, "\t\toperands[%v].access: WRITE\n", i)
		case CS_AC_READ | CS_AC_WRITE:
			fmt.Fprintf(buf, "\t\toperands[%v].access: READ | WRITE\n", i)
		}
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

	if insn.X86.EFlags != 0 {
		fmt.Fprintf(buf, "\tEFLAGS:")
		for i := uint(0); i <= 63; i++ {
			if insn.X86.EFlags&uint64(1<<i) != 0 {
				fmt.Fprintf(buf, " %s", getEFlagName(uint64(1<<i)))
			}
		}
		fmt.Fprintf(buf, "\n")
	}

	if insn.X86.FPUFlags != 0 {
		fmt.Fprintf(buf, "\tFPU_FLAGS:")
		for i := uint(0); i <= 63; i++ {
			if insn.X86.FPUFlags&uint64(1<<i) != 0 {
				fmt.Fprintf(buf, " %s", getFPUFlagName(uint64(1<<i)))
			}
		}
		fmt.Fprintf(buf, "\n")
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
