/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the _test.go files.

	Library Author: Ngyuen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details

(c) 2013 COSEINC. All Rights Reserved.
*/
package gapstone

// #cgo CFLAGS: -I/usr/include/capstone
// #cgo LDFLAGS: -lcapstone
// #include <stdlib.h>
// #include <capstone.h>
import "C"
import "unsafe"
import "reflect"
import "fmt"

// The Arch and Mode given at create time will determine how code is
// disassembled. After use you must close an Engine with engine.Close() to allow
// the C lib to free resources.
type Engine struct {
	handle C.csh
	Arch   uint
	Mode   uint
}

// Information that exists for every Instruction, regardless of Arch. Structure
// members here will be promoted, so every Instruction will have them available.
type InstructionHeader struct {
	Id               uint
	Address          uint
	Size             uint
	Mnemonic         string
	OpStr            string
	RegistersRead    []uint
	RegistersWritten []uint
	Groups           []uint
}

// Arch specific information will be filled in for exactly one of the
// substructures. Eg, an Engine created with New(CS_ARCH_ARM, CS_MODE_ARM) will
// fill in only the Arm structure member.
type Instruction struct {
	InstructionHeader
	Arm   ArmInstruction
	Arm64 Arm64Instruction
	Mips  MipsInstruction
	X86   X86Instruction
}

func fillGenericHeader(raw C.cs_insn, insn *Instruction) {
	insn.Id = uint(raw.id)
	insn.Address = uint(raw.address)
	insn.Size = uint(raw.size)
	insn.Mnemonic = C.GoString(&raw.mnemonic[0])
	insn.OpStr = C.GoString(&raw.op_str[0])
	for i := 0; raw.regs_read[i] != 0; i++ {
		insn.RegistersRead = append(insn.RegistersRead, uint(raw.regs_read[i]))
	}
	for i := 0; raw.regs_write[i] != 0; i++ {
		insn.RegistersWritten = append(insn.RegistersWritten, uint(raw.regs_write[i]))
	}
	for i := 0; raw.groups[i] != 0; i++ {
		insn.Groups = append(insn.Groups, uint(raw.groups[i]))
	}
}

// Close the underlying C handle and resources used by this Engine
func (e Engine) Close() (bool, error) {
	res, err := C.cs_close(e.handle)
	return bool(res), err
}

// Version information.
func (e Engine) Version() (maj, min int) {
	C.cs_version((*C.int)(unsafe.Pointer(&maj)), (*C.int)(unsafe.Pointer(&min)))
	return
}

// The Arch is implicit in the Engine. See also the toplevel RegName() function.
func (e Engine) RegName(reg uint) string {
	return C.GoString(C.cs_reg_name(e.handle, C.uint(reg)))
}

// The Arch is implicit in the Engine. See also the toplevel InsnName() function.
func (e Engine) InsnName(insn uint) string {
	return C.GoString(C.cs_insn_name(e.handle, C.uint(insn)))
}

// Disassemble a []byte full of code.
//   * offset - Starting offset to use. Will determine the Address that is created for disassembled instructions.
//   * count - Number of instructions to disassemble, 0 to disassemble the whole []byte
//
// Underlying C resources are automatically free'd by this function.
func (e Engine) Disasm(input []byte, offset, count uint64) ([]Instruction, error) {

	var insn *C.cs_insn
	bptr := (*C.char)(unsafe.Pointer(&input[0]))

	disassembled := C.cs_disasm_dyn(
		e.handle,
		bptr,
		C.uint64_t(len(input)),
		C.uint64_t(offset),
		C.uint64_t(count),
		&insn,
	)

	if disassembled > 0 {
		defer C.cs_free(unsafe.Pointer(insn))
		// Create a slice, and reflect its header
		var insns []C.cs_insn
		h := (*reflect.SliceHeader)(unsafe.Pointer(&insns))
		// Manually fill in the ptr, len and cap from the raw C data
		h.Data = uintptr(unsafe.Pointer(insn))
		h.Len = int(disassembled)
		h.Cap = int(disassembled)

		switch e.Arch {
		case CS_ARCH_ARM:
			return decomposeArm(insns), nil
		case CS_ARCH_ARM64:
			return decomposeArm64(insns), nil
		case CS_ARCH_MIPS:
			return decomposeMips(insns), nil
		case CS_ARCH_X86:
			return decomposeX86(insns), nil
		default:
			panic("Internal error - unknown engine archiecture?")
		}
	}
	return nil, fmt.Errorf("Disassembly failed.")
}

// Create a new Engine with the specified Arch and Mode
func New(arch, mode uint) (Engine, error) {
	var handle C.csh
	res, err := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if res {
		return Engine{handle, arch, mode}, nil
	}
	// Set an invalid Arch so if the user doesn't check err and tries to
	// disassemble with this engine then Disasm will panic.
	return Engine{0, CS_ARCH_MAX, 0}, err
}

// Look up the register name for a constant without creating a new Engine
func RegName(arch, reg uint) string {
	return C.GoString(C.cs_reg_name(C.csh(arch), C.uint(reg)))
}

// Look up the Instruction name for a constant without creating a new Engine
func InsnName(arch, insn uint) string {
	return C.GoString(C.cs_insn_name(C.csh(arch), C.uint(insn)))
}
