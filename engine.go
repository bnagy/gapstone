/*
Gapstone is a Go binding for the Capstone disassembly library. For examples,
try reading the *_test.go files.

	Library Author: Nguyen Anh Quynh
	Binding Author: Ben Nagy
	License: BSD style - see LICENSE file for details
    (c) 2013 COSEINC. All Rights Reserved.
*/
package gapstone

// #cgo pkg-config: capstone
// #include <stdlib.h>
// #include <capstone.h>
import "C"
import "unsafe"
import "reflect"
import "fmt"

type Errno int

func (e Errno) Error() string {
	s := C.GoString(C.cs_strerror(C.cs_err(e)))
	if s == "" {
		return fmt.Sprintf("Internal Error: No Error string for Errno %v", e)
	}
	return s
}

var (
	ErrOK       error = Errno(0)
	ErrOOM      error = Errno(1)
	ErrArch     error = Errno(2)
	ErrHandle   error = Errno(3)
	ErrArg      error = Errno(4)
	ErrMode     error = Errno(5)
	ErrOption   error = Errno(6)
	ErrDetail   error = Errno(7)
	ErrMemSetup error = Errno(8)
	ErrVersion  error = Errno(9)
	ErrDiet     error = Errno(10)
)

// Since this is a build-time option for the C lib, it seems logical to have
// this as a static flag.
// Diet Mode Changes:
// - No regs_read, regs_written or groups
// - No response to reg_name or insn_name
// - No mnemonic or op_str
// If you want to see any operands in diet mode, then you need CS_DETAIL.
var dietMode = bool(C.cs_support(CS_SUPPORT_DIET))

// The arch and mode given at create time will determine how code is
// disassembled. After use you must close an Engine with engine.Close() to allow
// the C lib to free resources.
type Engine struct {
	handle C.csh
	arch   int
	mode   uint
}

// Information that exists for every Instruction, regardless of arch.
// Structure members here will be promoted, so every Instruction will have
// them available. Check the constants for each architecture for available
// Instruction groups etc.
type InstructionHeader struct {
	Id      uint   // Internal id for this instruction. Subject to change.
	Address uint   // Nominal address ($ip) of this instruction
	Size    uint   // Size of the instruction, in bytes
	Bytes   []byte // Raw Instruction bytes
	// Not available in diet mode ( capstone built with CAPSTONE_DIET=yes )
	Mnemonic string // Ascii text of instruction mnemonic
	OpStr    string // Ascii text of instruction operands - Syntax depends on CS_OPT_SYNTAC
	// Not available without the decomposer. BE CAREFUL! By default,
	// CS_OPT_DETAIL is set to CS_OPT_OFF so the result of accessing these
	// members is undefined.
	RegistersRead    []uint // List of implicit registers read by this instruction
	RegistersWritten []uint // List of implicit registers written by this instruction
	Groups           []uint // List of *_GRP_* groups this instruction belongs to.
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
	PPC   PPCInstruction
}

// Called by the arch specific decomposers
func fillGenericHeader(raw C.cs_insn, insn *Instruction) {

	insn.Id = uint(raw.id)
	insn.Address = uint(raw.address)
	insn.Size = uint(raw.size)

	if !dietMode {
		insn.Mnemonic = C.GoString(&raw.mnemonic[0])
		insn.OpStr = C.GoString(&raw.op_str[0])
	}

	var bslice []byte
	h := (*reflect.SliceHeader)(unsafe.Pointer(&bslice))
	h.Data = uintptr(unsafe.Pointer(&raw.bytes[0]))
	h.Len = int(raw.size)
	h.Cap = int(raw.size)
	insn.Bytes = bslice

	if raw.detail != nil && !dietMode {
		for i := 0; i < int(raw.detail.regs_read_count); i++ {
			insn.RegistersRead = append(insn.RegistersRead, uint(raw.detail.regs_read[i]))
		}

		for i := 0; i < int(raw.detail.regs_write_count); i++ {
			insn.RegistersWritten = append(insn.RegistersWritten, uint(raw.detail.regs_write[i]))
		}

		for i := 0; i < int(raw.detail.groups_count); i++ {
			insn.Groups = append(insn.Groups, uint(raw.detail.groups[i]))
		}
	}

}

// Close the underlying C handle and resources used by this Engine
func (e Engine) Close() error {
	res := C.cs_close(&e.handle)
	return Errno(res)
}

// Accessor for the Engine architecture CS_ARCH_*
func (e Engine) Arch() int { return e.arch }

// Accessor for the Engine mode CS_MODE_*
func (e Engine) Mode() uint { return e.mode }

// Check if a particular arch is supported by this engine.
// To verify if this engine supports everything, use CS_ARCH_ALL
func (e Engine) Support(arch int) bool { return bool(C.cs_support(C.int(arch))) }

// Version information.
func (e Engine) Version() (maj, min int) {
	C.cs_version((*C.int)(unsafe.Pointer(&maj)), (*C.int)(unsafe.Pointer(&min)))
	return
}

// Getter for the last Errno from the engine. Normal code shouldn't need to
// access this directly, but it's exported just in case.
func (e Engine) Errno() error { return Errno(C.cs_errno(e.handle)) }

// The arch is implicit in the Engine. Accepts either a constant like ARM_REG_R0
// or insn.Arm.Operands[0].Reg, or anything that refers to a Register like
// insn.X86.SibBase etc
//
// WARNING: Always returns "" if capstone built with CAPSTONE_DIET
func (e Engine) RegName(reg uint) string {
	if dietMode {
		return ""
	}
	return C.GoString(C.cs_reg_name(e.handle, C.uint(reg)))
}

// The arch is implicit in the Engine. Accepts a constant like
// ARM_INSN_ADD, or insn.Id
//
// WARNING: Always returns "" if capstone built with CAPSTONE_DIET
func (e Engine) InsnName(insn uint) string {
	if dietMode {
		return ""
	}
	return C.GoString(C.cs_insn_name(e.handle, C.uint(insn)))
}

// Setter for Engine options CS_OPT_*
func (e Engine) SetOption(ty, value uint) error {
	res := C.cs_option(
		e.handle,
		C.cs_opt_type(ty),
		C.size_t(value),
	)

	if Errno(res) == ErrOK {
		return nil
	}
	return Errno(res)
}

// Disassemble a []byte full of opcodes.
//   * address - Address of the first instruction in the given code buffer.
//   * count - Number of instructions to disassemble, 0 to disassemble the whole []byte
//
// Underlying C resources are automatically free'd by this function.
func (e Engine) Disasm(input []byte, address, count uint64) ([]Instruction, error) {

	var insn *C.cs_insn
	bptr := (*C.uint8_t)(unsafe.Pointer(&input[0]))
	disassembled := C.cs_disasm_ex(
		e.handle,
		bptr,
		C.size_t(len(input)),
		C.uint64_t(address),
		C.size_t(count),
		&insn,
	)

	if disassembled > 0 {
		defer C.cs_free((*C.cs_insn)(unsafe.Pointer(insn)), C.size_t(disassembled))
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
		case CS_ARCH_PPC:
			return decomposePPC(insns), nil
		default:
			return []Instruction{}, ErrArch
		}
	}
	return []Instruction{}, e.Errno()
}

// Create a new Engine with the specified arch and mode
func New(arch int, mode uint) (Engine, error) {
	var handle C.csh
	res := C.cs_open(C.cs_arch(arch), C.cs_mode(mode), &handle)
	if Errno(res) == ErrOK {
		return Engine{handle, arch, mode}, nil
	}
	return Engine{0, CS_ARCH_MAX, 0}, Errno(res)
}
