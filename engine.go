/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

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

type Errno int

func (e Errno) Error() string {
	s := errText[e]
	if s == "" {
		return fmt.Sprintf("cs_errno: %d (%v)", e, int(e))
	}
	return s
}

var (
	ErrOK     error = Errno(0)
	ErrOOM    error = Errno(1)
	ErrArch   error = Errno(2)
	ErrHandle error = Errno(3)
)

var errText = map[Errno]string{
	0: "cs_errno: 0 (No error)",
	1: "cs_errno: 1 (Out of Memory)",
	2: "cs_errno: 2 (Unsupported Architecture)",
	3: "cs_errno: 3 (Invalid Handle)",
}

// The arch and mode given at create time will determine how code is
// disassembled. After use you must close an Engine with engine.Close() to allow
// the C lib to free resources.
type Engine struct {
	handle C.csh
	arch   uint
	mode   uint
}

// Information that exists for every Instruction, regardless of arch. Structure
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

// arch specific information will be filled in for exactly one of the
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
func (e Engine) Close() error {
	res := C.cs_close(e.handle)
	return Errno(res)
}

// Accessor for the Engine architecture CS_ARCH_*
func (e Engine) Arch() uint { return e.arch }

// Accessor for the Engine mode CS_MODE_*
func (e Engine) Mode() uint { return e.mode }

// Version information.
func (e Engine) Version() (maj, min int) {
	C.cs_version((*C.int)(unsafe.Pointer(&maj)), (*C.int)(unsafe.Pointer(&min)))
	return
}

func (e Engine) Errno() error { return Errno(C.cs_errno(e.handle)) }

// The arch is implicit in the Engine. Accepts either a constant like ARM_REG_R0
// or insn.Arm.Operands[0].Reg, or anything that refers to a Register like
// insn.X86.SibBase etc
func (e Engine) RegName(reg uint) string {
	return C.GoString(C.cs_reg_name(e.handle, C.uint(reg)))
}

// The arch is implicit in the Engine. Accepts a constant like
// ARM_INSN_ADD, or insn.Id
func (e Engine) InsnName(insn uint) string {
	return C.GoString(C.cs_insn_name(e.handle, C.uint(insn)))
}

// Disassemble a []byte full of opcodes.
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

		switch e.arch {
		case CS_ARCH_ARM:
			return decomposeArm(insns), nil
		case CS_ARCH_ARM64:
			return decomposeArm64(insns), nil
		case CS_ARCH_MIPS:
			return decomposeMips(insns), nil
		case CS_ARCH_X86:
			return decomposeX86(insns), nil
		default:
			return nil, ErrArch
		}
	}
	return []Instruction{}, e.Errno()
}

// Create a new Engine with the specified arch and mode
func New(arch, mode uint) (Engine, error) {
	var handle C.csh
	res := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if Errno(res) == ErrOK {
		return Engine{handle, arch, mode}, nil
	}
	return Engine{0, CS_ARCH_MAX, 0}, Errno(res)
}
