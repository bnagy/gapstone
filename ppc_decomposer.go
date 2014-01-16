package gapstone

// #cgo LDFLAGS: -lcapstone
// #include <stdlib.h>
// #include <capstone/capstone.h>
import "C"
import "unsafe"
import "reflect"

//import "fmt"

// Accessed via insn.PPC.XXX
type PPCInstruction struct {
	BC        int
	BH        int
	UpdateCR0 bool
	Operands  []PPCOperand
}

// Number of Operands of a given PPC_OP_* type
func (insn PPCInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type PPCOperand struct {
	Type uint // PPC_OP_* - determines which field is set below
	Reg  uint
	Imm  int
	Mem  PPCMemoryOperand
}

type PPCMemoryOperand struct {
	Base uint
	Disp int
}

func fillPPCHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_ppc := (*C.cs_ppc)(unsafe.Pointer(&raw.detail.anon0[0]))

	ppc := new(PPCInstruction)

	// Set the insn members
	ppc.BC = int(cs_ppc.bc)
	ppc.BH = int(cs_ppc.bh)
	ppc.UpdateCR0 = bool(cs_ppc.update_cr0)

	// Cast the op_info to a []C.cs_ppc_op
	var ops []C.cs_ppc_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_ppc.operands[0]))
	oih.Len = int(cs_ppc.op_count)
	oih.Cap = int(cs_ppc.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == PPC_OP_INVALID {
			break
		}

		gop := new(PPCOperand)
		gop.Type = uint(cop._type)

		switch cop._type {
		// fake a union by setting only the correct struct member
		case PPC_OP_IMM:
			gop.Imm = int(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case PPC_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case PPC_OP_MEM:
			gmop := new(PPCMemoryOperand)
			cmop := (*C.ppc_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gmop.Base = uint(cmop.base)
			gmop.Disp = int(cmop.disp)
			gop.Mem = *gmop
		}

		ppc.Operands = append(ppc.Operands, *gop)

	}
	insn.PPC = *ppc
}

func decomposePPC(raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(raw, decomp)
		fillPPCHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
