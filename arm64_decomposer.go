package gapstone

// #cgo pkg-config: capstone
// #include <stdlib.h>
// #include <capstone.h>
import "C"
import "unsafe"
import "reflect"

//import "log"

// Accessed via insn.Arm64.XXX
type Arm64Instruction struct {
	CC          uint
	UpdateFlags bool
	Writeback   bool
	Operands    []Arm64Operand
}

type Arm64Shifter struct {
	Type  uint
	Value uint
}

type Arm64Operand struct {
	Shift Arm64Shifter
	Ext   uint
	Type  uint // ARM64_OP_* - determines which field is set below
	Reg   uint
	Imm   int64
	FP    float64
	Mem   Arm64MemoryOperand
}

type Arm64MemoryOperand struct {
	Base  uint
	Index uint
	Disp  int64
}

// Number of Operands of a given ARM64_OP_* type
func (insn Arm64Instruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

func fillArm64Header(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	arm64 := new(Arm64Instruction)
	// Cast the cs_detail union
	cs_arm64 := (*C.cs_arm64)(unsafe.Pointer(&raw.detail.anon0[0]))

	arm64.CC = uint(cs_arm64.cc)
	arm64.UpdateFlags = bool(cs_arm64.update_flags)
	arm64.Writeback = bool(cs_arm64.writeback)

	// Cast the op_info to a []C.cs_arm6464_op
	var ops []C.cs_arm64_op
	h := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	h.Data = uintptr(unsafe.Pointer(&cs_arm64.operands[0]))
	h.Len = int(cs_arm64.op_count)
	h.Cap = int(cs_arm64.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == ARM64_OP_INVALID {
			break
		}

		gop := new(Arm64Operand)
		gop.Shift.Type = uint(cop.shift._type)
		gop.Shift.Value = uint(cop.shift.value)
		gop.Type = uint(cop._type)
		gop.Ext = uint(cop.ext)

		switch cop._type {
		// fake a union by setting only the correct struct member
		case ARM64_OP_IMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case ARM64_OP_FP:
			gop.FP = float64(*(*C.double)(unsafe.Pointer(&cop.anon0[0])))
		case ARM64_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case ARM64_OP_MEM:
			gmop := new(Arm64MemoryOperand)
			cmop := (*C.arm64_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gmop.Base = uint(cmop.base)
			gmop.Index = uint(cmop.index)
			gmop.Disp = int64(cmop.disp)
			gop.Mem = *gmop
		}

		arm64.Operands = append(arm64.Operands, *gop)

	}
	insn.Arm64 = *arm64
}

func decomposeArm64(raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(raw, decomp)
		fillArm64Header(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
