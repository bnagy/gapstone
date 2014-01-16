package gapstone

// #cgo LDFLAGS: -lcapstone
// #include <stdlib.h>
// #include <capstone/capstone.h>
import "C"
import "unsafe"
import "reflect"

// Accessed via insn.Arm.XXX
type ArmInstruction struct {
	CC          uint
	UpdateFlags bool
	Writeback   bool
	Operands    []ArmOperand
}

type ArmShifter struct {
	Type  uint
	Value uint
}

type ArmOperand struct {
	Shift ArmShifter
	Type  uint // ARM_OP_* - determines which field is set below
	Reg   uint
	Imm   int64
	FP    float64
	Mem   ArmMemoryOperand
}

type ArmMemoryOperand struct {
	Base  uint
	Index uint
	Scale int
	Disp  int64
}

// Number of Operands of a given ARM_OP_* type
func (insn ArmInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

func fillArmHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_arm := (*C.cs_arm)(unsafe.Pointer(&raw.detail.anon0[0]))

	arm := new(ArmInstruction)
	arm.CC = uint(cs_arm.cc)
	arm.UpdateFlags = bool(cs_arm.update_flags)
	arm.Writeback = bool(cs_arm.writeback)

	// Cast the op_info to a []C.cs_arm_op
	var ops []C.cs_arm_op
	h := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	h.Data = uintptr(unsafe.Pointer(&cs_arm.operands[0]))
	h.Len = int(cs_arm.op_count)
	h.Cap = int(cs_arm.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {
		if cop._type == ARM_OP_INVALID {
			break
		}
		gop := new(ArmOperand)
		gop.Shift.Type = uint(cop.shift._type)
		gop.Shift.Value = uint(cop.shift.value)
		gop.Type = uint(cop._type)
		switch cop._type {
		// fake a union by setting only the correct struct member
		case ARM_OP_IMM, ARM_OP_CIMM, ARM_OP_PIMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case ARM_OP_FP:
			gop.FP = float64(*(*C.double)(unsafe.Pointer(&cop.anon0[0])))
		case ARM_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case ARM_OP_MEM:
			gmop := new(ArmMemoryOperand)
			cmop := (*C.arm_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gmop.Base = uint(cmop.base)
			gmop.Index = uint(cmop.index)
			gmop.Scale = int(cmop.scale)
			gmop.Disp = int64(cmop.disp)
			gop.Mem = *gmop
		}
		arm.Operands = append(arm.Operands, *gop)
	}
	insn.Arm = *arm
}

func decomposeArm(raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(raw, decomp)
		fillArmHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
