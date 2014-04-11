package gapstone

// #cgo pkg-config: capstone
// #include <stdlib.h>
// #include <capstone.h>
import "C"
import "unsafe"
import "reflect"

//import "fmt"

// Accessed via insn.Sparc.XXX
type SparcInstruction struct {
	CC       uint
	Hint     uint
	OpCnt    uint8
	Operands []SparcOperand
}

// Number of Operands of a given SPARC_OP_* type
func (insn SparcInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type SparcOperand struct {
	Type uint // SPARC_OP_* - determines which field is set below
	Reg  uint
	Imm  int32
	Mem  SparcMemoryOperand
}

type SparcMemoryOperand struct {
	Base  uint8
	Index uint8
	Disp  int32
}

func fillSparcHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_sparc := (*C.cs_sparc)(unsafe.Pointer(&raw.detail.anon0[0]))

	sparc := new(SparcInstruction)

	sparc.CC = uint(cs_sparc.cc)
	sparc.Hint = uint(cs_sparc.hint)
	sparc.OpCnt = uint8(cs_sparc.op_count)

	// Cast the op_info to a []C.cs_sparc_op
	var ops []C.cs_sparc_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_sparc.operands[0]))
	oih.Len = int(cs_sparc.op_count)
	oih.Cap = int(cs_sparc.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == SPARC_OP_INVALID {
			break
		}

		gop := new(SparcOperand)
		gop.Type = uint(cop._type)

		switch cop._type {
		// fake a union by setting only the correct struct member
		case SPARC_OP_IMM:
			gop.Imm = int32(*(*C.int32_t)(unsafe.Pointer(&cop.anon0[0])))
		case SPARC_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case SPARC_OP_MEM:
			gmop := new(SparcMemoryOperand)
			cmop := (*C.sparc_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gmop.Base = uint8(cmop.base)
			gmop.Index = uint8(cmop.index)
			gmop.Disp = int32(cmop.disp)
			gop.Mem = *gmop
		}

		sparc.Operands = append(sparc.Operands, *gop)

	}
	insn.Sparc = *sparc
}

func decomposeSparc(raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(raw, decomp)
		fillSparcHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
