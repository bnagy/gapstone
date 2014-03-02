package gapstone

// #cgo pkg-config: capstone
// #include <stdlib.h>
// #include <capstone.h>
import "C"

const (
	// Engine Architectures
	CS_ARCH_ARM   = C.CS_ARCH_ARM   // ARM architecture (including Thumb Thumb-2)
	CS_ARCH_ARM64 = C.CS_ARCH_ARM64 // ARM-64, also called AArch64
	CS_ARCH_MIPS  = C.CS_ARCH_MIPS  // Mips architecture
	CS_ARCH_X86   = C.CS_ARCH_X86   // X86 architecture (including x86 & x86-64)
	CS_ARCH_PPC   = C.CS_ARCH_PPC   // PowerPC architecture
	CS_ARCH_MAX   = C.CS_ARCH_MAX
	CS_ARCH_ALL   = C.CS_ARCH_ALL
)

const (
	// Engine Modes
	CS_MODE_LITTLE_ENDIAN = C.CS_MODE_LITTLE_ENDIAN // little endian mode (default mode)
	CS_MODE_ARM           = C.CS_MODE_ARM           // 32-bit ARM
	CS_MODE_16            = C.CS_MODE_16            // 16-bit mode
	CS_MODE_32            = C.CS_MODE_32            // 32-bit mode
	CS_MODE_64            = C.CS_MODE_64            // 64-bit mode
	CS_MODE_THUMB         = C.CS_MODE_THUMB         // ARM's Thumb mode including Thumb-2
	CS_MODE_MICRO         = C.CS_MODE_MICRO         // MicroMips mode (MIPS architecture)
	CS_MODE_N64           = C.CS_MODE_N64           // Nintendo-64 mode (MIPS architecture)
	CS_MODE_BIG_ENDIAN    = 1 << 31                 // big endian mode
)

const (
	// Engine Options types
	CS_OPT_SYNTAX = C.CS_OPT_SYNTAX // Asssembly output syntax
	CS_OPT_DETAIL = C.CS_OPT_DETAIL // Break down instruction structure into details
	CS_OPT_MODE   = C.CS_OPT_MODE   // Change engine's mode at run-time
	CS_OPT_MEM    = C.CS_OPT_MEM    // User-defined memory malloc/calloc/free
)

const (
	// Engine Options values
	CS_OPT_OFF              = C.CS_OPT_OFF              // Turn OFF an option - default option for CS_OPT_DETAIL.
	CS_OPT_ON               = C.CS_OPT_ON               // Turn ON an option (CS_OPT_DETAIL).
	CS_OPT_SYNTAX_DEFAULT   = C.CS_OPT_SYNTAX_DEFAULT   // Default asm syntax (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_INTEL     = C.CS_OPT_SYNTAX_INTEL     // X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_ATT       = C.CS_OPT_SYNTAX_ATT       // X86 ATT asm syntax (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_NOREGNAME = C.CS_OPT_SYNTAX_NOREGNAME // PPC asm syntax: Prints register name with only number (CS_OPT_SYNTAX)
)

const (
	// All type of errors encountered by Capstone API.
	// These are values returned by cs_errno()
	CS_ERR_OK       = C.CS_ERR_OK       // No error: everything was fine
	CS_ERR_MEM      = C.CS_ERR_MEM      // Out-Of-Memory error: cs_open(), cs_disasm_ex()
	CS_ERR_ARCH     = C.CS_ERR_ARCH     // Unsupported architecture: cs_open()
	CS_ERR_HANDLE   = C.CS_ERR_HANDLE   // Invalid handle: cs_op_count(), cs_op_index()
	CS_ERR_CSH      = C.CS_ERR_CSH      // Invalid csh argument: cs_close(), cs_errno(), cs_option()
	CS_ERR_MODE     = C.CS_ERR_MODE     // Invalid/unsupported mode: cs_open()
	CS_ERR_OPTION   = C.CS_ERR_OPTION   // Invalid/unsupported option: cs_option()
	CS_ERR_DETAIL   = C.CS_ERR_DETAIL   // Information is unavailable because detail option is OFF
	CS_ERR_MEMSETUP = C.CS_ERR_MEMSETUP // Dynamic memory management uninitialized (see CS_OPT_MEM)
	CS_ERR_VERSION  = C.CS_ERR_VERSION  // Unsupported version (bindings)
	CS_ERR_DIET     = C.CS_ERR_DIET     // Information irrelevant in diet engine
)

const CS_SUPPORT_DIET = C.CS_SUPPORT_DIET
