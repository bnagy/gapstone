/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

	Library Author: Nguyen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details
    (c) 2013 COSEINC. All Rights Reserved.
*/

package gapstone

// #cgo LDFLAGS: -lcapstone
// #cgo freebsd CFLAGS: -I/usr/local/include
// #cgo freebsd LDFLAGS: -L/usr/local/lib
// #include <stdlib.h>
// #include <capstone/capstone.h>
import "C"
import "unsafe"
import "reflect"

//import "fmt"

// Accessed via insn.X86.XXX
type X86Instruction struct {
	Prefix   []byte
	Segment  uint
	Opcode   []byte
	OpSize   byte
	AddrSize byte
	DispSize byte
	ImmSize  byte
	ModRM    byte
	Sib      byte
	Disp     int
	SibIndex uint
	SibScale int8
	SibBase  uint
	Operands []X86Operand
}

// Number of Operands of a given X86_OP_* type
func (insn X86Instruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

type X86Operand struct {
	Type uint // X86_OP_* - determines which field is set below
	Reg  uint
	Imm  int64
	FP   float64
	Mem  X86MemoryOperand
}

type X86MemoryOperand struct {
	Base  uint
	Index uint
	Scale int
	Disp  int64
}

func fillX86Header(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_x86 := (*C.cs_x86)(unsafe.Pointer(&raw.detail.anon0[0]))

	// cast the prefix array to a []byte
	var pref []byte
	ph := (*reflect.SliceHeader)(unsafe.Pointer(&pref))
	ph.Data = uintptr(unsafe.Pointer(&cs_x86.prefix[0]))
	ph.Len = 5
	ph.Cap = 5

	// Same for the opcode array
	var opc []byte
	oh := (*reflect.SliceHeader)(unsafe.Pointer(&opc))
	oh.Data = uintptr(unsafe.Pointer(&cs_x86.opcode[0]))
	oh.Len = 3
	oh.Cap = 3

	x86 := X86Instruction{
		Prefix:   pref,
		Segment:  uint(cs_x86.segment),
		Opcode:   opc,
		OpSize:   byte(cs_x86.op_size),
		AddrSize: byte(cs_x86.addr_size),
		DispSize: byte(cs_x86.disp_size),
		ImmSize:  byte(cs_x86.imm_size),
		ModRM:    byte(cs_x86.modrm),
		Sib:      byte(cs_x86.sib),
		Disp:     int(cs_x86.disp),
		SibIndex: uint(cs_x86.sib_index),
		SibScale: int8(cs_x86.sib_scale),
		SibBase:  uint(cs_x86.sib_base),
	}

	// Cast the op_info to a []C.cs_x86_op
	var ops []C.cs_x86_op
	oih := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	oih.Data = uintptr(unsafe.Pointer(&cs_x86.operands[0]))
	oih.Len = int(cs_x86.op_count)
	oih.Cap = int(cs_x86.op_count)

	// Create the Go object for each operand
	for _, cop := range ops {

		if cop._type == X86_OP_INVALID {
			break
		}

		gop := new(X86Operand)
		gop.Type = uint(cop._type)

		switch cop._type {
		// fake a union by setting only the correct struct member
		case X86_OP_IMM:
			gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
		case X86_OP_FP:
			gop.FP = float64(*(*C.double)(unsafe.Pointer(&cop.anon0[0])))
		case X86_OP_REG:
			gop.Reg = uint(*(*C.uint)(unsafe.Pointer(&cop.anon0[0])))
		case X86_OP_MEM:
			cmop := (*C.x86_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = X86MemoryOperand{
				Base:  uint(cmop.base),
				Index: uint(cmop.index),
				Scale: int(cmop.scale),
				Disp:  int64(cmop.disp),
			}
		}

		x86.Operands = append(x86.Operands, *gop)
	}

	insn.X86 = x86
}

func decomposeX86(raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := new(Instruction)
		fillGenericHeader(raw, decomp)
		fillX86Header(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
