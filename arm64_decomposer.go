package gapstone

// #cgo CFLAGS: -I/usr/include/capstone
// #cgo LDFLAGS: -lcapstone
// #include <stdlib.h>
// #include <capstone.h>
import "C"
import "unsafe"
import "reflect"

//import "fmt"

type Arm64OpType uint
type Arm64ShiftType uint
type Arm64CC uint
type Arm64Extender uint

type Arm64Instruction struct {
	CC          Arm64CC
	UpdateFlags bool
	Writeback   bool
	Operands    []Arm64Operand
}

type Arm64Shifter struct {
	Type  Arm64ShiftType
	Value uint
}

type Arm64Operand struct {
	Shift Arm64Shifter
	Ext   Arm64Extender
	Type  Arm64OpType
	Reg   uint // Only ONE of these four will be set
	Imm   int64
	FP    float64
	Mem   Arm64MemoryOperand
}

type Arm64MemoryOperand struct {
	Base  uint
	Index uint
	Disp  int64
}

func fillArm64Header(raw C.cs_insn, insn *Instruction) {
	arm64 := new(Arm64Instruction)
	// Parse the cs_arm64 union header
	cs_arm64 := (*C.cs_arm64)(unsafe.Pointer(&raw.anon0[0]))
	arm64.CC = Arm64CC(cs_arm64.cc)
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
		gop.Shift.Type = Arm64ShiftType(cop.shift._type)
		gop.Shift.Value = uint(cop.shift.value)
		gop.Type = Arm64OpType(cop._type)
		gop.Ext = Arm64Extender(cop.ext)

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

func DecomposeArm64(raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(raw, decomp)
		fillArm64Header(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
