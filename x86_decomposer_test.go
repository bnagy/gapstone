package gapstone

import "testing"
import "bytes"
import "fmt"
import "io/ioutil"

func x86InsnDetail(insn Instruction, engine *Engine, buf *bytes.Buffer) {
	fmt.Fprintf(buf, "\tPrefix:")
	dumpHex(insn.X86.Prefix, buf)

	if insn.X86.Segment != X86_REG_INVALID {
		fmt.Fprintf(
			buf,
			"\tSegment override: %s\n",
			engine.RegName(insn.X86.Segment),
		)
	}

	fmt.Fprintf(buf, "\tOpcode:")
	dumpHex(insn.X86.Opcode, buf)
	fmt.Fprintf(
		buf,
		"\top_size: %v, addr_size: %v, disp_size: %v, imm_size: %v\n",
		insn.X86.OpSize,
		insn.X86.AddrSize,
		insn.X86.DispSize,
		insn.X86.ImmSize,
	)
	fmt.Fprintf(buf, "\tmodrm: 0x%x\n", insn.X86.ModRM)
	fmt.Fprintf(buf, "\tdisp: 0x%x\n", uint32(insn.X86.Disp))

	// SIB is not available in 16-bit mode
	if (engine.Mode & CS_MODE_16) == 0 {
		fmt.Fprintf(buf, "\tsib: 0x%x\n", insn.X86.Sib)
		if insn.X86.SibIndex != X86_REG_INVALID {
			fmt.Fprintf(
				buf,
				"\tsib_index: %s, sib_scale: %v, sib_base: %s\n",
				RegName(CS_ARCH_X86, insn.X86.SibIndex),
				insn.X86.SibScale,
				engine.RegName(insn.X86.SibBase),
			)
		}
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

	fmt.Fprintf(buf, "\top_count: %v\n", len(insn.X86.Operands))

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
	}

	fmt.Fprintf(buf, "\n")
}

func TestX86(t *testing.T) {

	final := new(bytes.Buffer)
	spec_file := "x86.SPEC"

	for i, platform := range x86_tests {

		engine, err := New(platform.arch, platform.mode)
		if err != nil {
			t.Errorf("Failed to initialize engine %v", err)
			return
		}
		if i == 0 {
			maj, min := engine.Version()
			t.Logf("Arch: x86. Capstone Version: %v.%v", maj, min)
		}
		defer engine.Close()
		insns, err := engine.Disasm([]byte(platform.code), OFFSET, 0)
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
		//fmt.Println(fs)
		t.Errorf("Output failed to match spec!")
	} else {
		t.Logf("Clean diff with %v.\n", spec_file)
	}

}
