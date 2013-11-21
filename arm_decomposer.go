package gapstone

// #cgo CFLAGS: -I/usr/include/capstone
// #cgo LDFLAGS: -lcapstone
// #include <stdlib.h>
// #include <capstone.h>
import "C"
import "unsafe"
import "reflect"

type ArmOpType uint
type ArmShiftType uint
type ArmCC uint

type ArmInstruction struct {
	CC          ArmCC
	UpdateFlags bool
	Writeback   bool
	Operands    []ArmOperand
}

type ArmShifter struct {
	Type  ArmShiftType
	Value uint
}

type ArmOperand struct {
	Shift ArmShifter
	Type  ArmOpType
	Reg   uint // Only ONE of these four will be set
	Imm   int64
	FP    float64
	Mem   ArmMemoryOperand
}

type ArmMemoryOperand struct {
	Base  uint
	Index uint
	Scale int
	Disp  uint64
}

func fillGenericHeader(raw C.cs_insn, insn *Instruction) {
	insn.Id = uint(raw.id)
	insn.Address = uint(raw.address)
	insn.Size = uint(raw.size)
	insn.Mnemonic = C.GoString(&raw.mnemonic[0])
	insn.OpStr = C.GoString(&raw.op_str[0])
	for i := 0; raw.regs_read[i] != 0; i++ {
		insn.RegistersRead = append(insn.RegistersRead, Register(raw.regs_read[i]))
	}
	for i := 0; raw.regs_write[i] != 0; i++ {
		insn.RegistersWritten = append(insn.RegistersWritten, Register(raw.regs_write[i]))
	}
	for i := 0; raw.groups[i] != 0; i++ {
		insn.Groups = append(insn.Groups, Group(raw.groups[i]))
	}
}

func fillArmHeader(raw C.cs_insn, insn *Instruction) {
	arm := new(ArmInstruction)
	// Parse the cs_arm union header
	cs_arm := (*C.cs_arm)(unsafe.Pointer(&raw.anon0[0]))
	arm.CC = ArmCC(cs_arm.cc)
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
		gop.Shift.Type = ArmShiftType(cop.shift._type)
		gop.Shift.Value = uint(cop.shift.value)
		gop.Type = ArmOpType(cop._type)
		switch cop._type {
		// fake a union by setting only the correct struct member
		case ARM_OP_IMM:
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
			gmop.Disp = uint64(cmop.disp)
			gop.Mem = *gmop
		}
		arm.Operands = append(arm.Operands, *gop)
	}
	insn.Arm = *arm
}

func DecomposeArm(raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(raw, decomp)
		fillArmHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
