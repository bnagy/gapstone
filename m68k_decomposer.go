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

// Accessed via insn.M68k.XXX
type M68kInstruction struct {
	Operands   []M68kOperand
	OpSizeType uint
	OpSize     uint
}

type M68kOperand struct {
	AddressMode uint
	Type        uint // M68K_OP_* - determines which field is set below
	Imm         int64
	Dimm        float64
	Simm        float32
	Reg         uint
	Mem         M68kMemoryOperand
	RegBits     uint
}

type M68kMemoryOperand struct {
	BaseReg   uint
	IndexReg  uint
	InBaseReg uint
	InDisp    uint
	OutDisp   uint
	Disp      uint16
	Scale     uint8
	Bitfield  uint8
	Width     uint8
	Offset    uint8
	IndexSize uint8
}

// Number of Operands of a given M68K_OP_* type
func (insn M68kInstruction) OpCount(optype uint) int {
	count := 0
	for _, op := range insn.Operands {
		if op.Type == optype {
			count++
		}
	}
	return count
}

func fillM68kHeader(raw C.cs_insn, insn *Instruction) {

	if raw.detail == nil {
		return
	}

	// Cast the cs_detail union
	cs_m68k := (*C.cs_m68k)(unsafe.Pointer(&raw.detail.anon0[0]))

	m68k := M68kInstruction{
		OpSizeType: uint(cs_m68k.op_size._type),
	}
	// unpack the size union manually for the Go object

	switch cs_m68k.op_size._type {
	case M68K_SIZE_TYPE_CPU, M68K_SIZE_TYPE_FPU:
		m68k.OpSize = uint(*(*C.uint32_t)(unsafe.Pointer(&cs_m68k.op_size.anon0[0])))
	default:
		m68k.OpSizeType = M68K_SIZE_TYPE_INVALID
	}

	// Cast the operand pointer to a []C.cs_m68k_op
	var ops []C.cs_m68k_op
	h := (*reflect.SliceHeader)(unsafe.Pointer(&ops))
	h.Data = uintptr(unsafe.Pointer(&cs_m68k.operands[0]))
	h.Len = int(cs_m68k.op_count)
	h.Cap = int(cs_m68k.op_count)

	// Create the Go object for each operand
	for i, cop := range ops {
		if cop._type == M68K_OP_INVALID || i >= int(cs_m68k.op_count) {
			break
		}

		gop := M68kOperand{
			AddressMode: uint(cop.address_mode),
			Type:        uint(cop._type),
		}
		switch cop._type {
		// fake a union by setting only the correct struct member
		case M68K_OP_IMM:
			// TODO this is convoluted. Why doesn't the capstone arch have separate
			// enums for OP_IMM, OP_SIMM and OP_DIMM ??
			switch m68k.OpSizeType {

			default:
				// do nothing, the OpSizeType has been set to invalid above

			case M68K_SIZE_TYPE_FPU:
				switch m68k.OpSize {
				default:
					// do nothing
				case M68K_FPU_SIZE_SINGLE:
					gop.Simm = float32(*(*C.float)(unsafe.Pointer(&cop.anon0[0])))
				case M68K_FPU_SIZE_DOUBLE:
					gop.Dimm = float64(*(*C.double)(unsafe.Pointer(&cop.anon0[0])))
				}

			case M68K_SIZE_TYPE_CPU:
				gop.Imm = int64(*(*C.int64_t)(unsafe.Pointer(&cop.anon0[0])))
			}

		case M68K_OP_REG:
			gop.Reg = uint(*(*C.m68k_reg)(unsafe.Pointer(&cop.anon0[0])))
		case M68K_OP_REG_BITS, M68K_OP_REG_PAIR: // TODO is this where REG_PAIR goes??
			gop.RegBits = uint(*(*C.uint64_t)(unsafe.Pointer(&cop.anon0[0])))
		case M68K_OP_MEM:
			cmop := (*C.m68k_op_mem)(unsafe.Pointer(&cop.anon0[0]))
			gop.Mem = M68kMemoryOperand{
				BaseReg:   uint(cmop.base_reg),
				IndexReg:  uint(cmop.index_reg),
				InBaseReg: uint(cmop.in_base_reg),
				InDisp:    uint(cmop.in_disp),
				OutDisp:   uint(cmop.out_disp),
				Disp:      uint16(cmop.disp),
				Scale:     uint8(cmop.scale),
				Bitfield:  uint8(cmop.bitfield),
				Width:     uint8(cmop.width),
				Offset:    uint8(cmop.offset),
				IndexSize: uint8(cmop.index_size),
			}
		}

		m68k.Operands = append(m68k.Operands, gop)
	}
	insn.M68k = &m68k
}

func decomposeM68k(e *Engine, raws []C.cs_insn) []Instruction {
	decomposed := []Instruction{}
	for _, raw := range raws {
		decomp := &Instruction{}
		e.fillGenericHeader(raw, decomp)
		fillM68kHeader(raw, decomp)
		decomposed = append(decomposed, *decomp)
	}
	return decomposed
}
