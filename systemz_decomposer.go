package gapstone

// #cgo pkg-config: capstone
// #include <stdlib.h>
// #include <capstone.h>
import "C"
import "unsafe"
import "reflect"

//import "fmt"

// Accessed via insn.SysZ.XXX
type SysZInstruction struct {
	CC       uint
	OpCnt    uint8
	Operands []SysZOperand
}

// Number of Operands of a given SYSZ_OP_* type
func (insn SysZInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type SysZOperand struct {
	Type uint // SYSZ_OP_* - determines which field is set below
	Reg  uint
	Imm  int64
	Mem  SysZMemoryOperand
}

type SysZMemoryOperand struct {
	Base   uint8
	Index  uint8
	Length uint64
	Disp   int64
}

func fillSysZHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_sysz := (*C.cs_sysz)(unsafe.Pointer(&raw.detail.anon0[0]))

	sysz := new(SysZInstruction)
	sysz.CC = uint(cs_sysz.cc)
	sysz.OpCnt = uint8(cs_sysz.op_count)

	// Cast the op_info to a []C.cs_sysz_op
	var ops []C.cs_sysz_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_sysz.operands[0]))
	oih.Len = int(cs_sysz.op_count)
	oih.Cap = int(cs_sysz.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == SYSZ_OP_INVALID {
			break
		}

		gop := new(SysZOperand)
		gop.Type = uint(cop._type)

		switch cop._type {
		// fake a union by setting only the correct struct member
		case SYSZ_OP_IMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case SYSZ_OP_REG, SYSZ_OP_ACREG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case SYSZ_OP_MEM:
			gmop := new(SysZMemoryOperand)
			cmop := (*C.sysz_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gmop.Base = uint8(cmop.base)
			gmop.Index = uint8(cmop.index)
			gmop.Length = uint64(cmop.length)
			gmop.Disp = int64(cmop.disp)
			gop.Mem = *gmop
		}

		sysz.Operands = append(sysz.Operands, *gop)

	}
	insn.SysZ = *sysz
}

func decomposeSysZ(raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(raw, decomp)
		fillSysZHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
