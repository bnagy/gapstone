package gapstone

const (
	// Engine Architectures
	CS_ARCH_ARM   = iota // ARM architecture (including Thumb Thumb-2)
	CS_ARCH_ARM64        // ARM-64, also called AArch64
	CS_ARCH_MIPS         // Mips architecture
	CS_ARCH_X86          // X86 architecture (including x86 & x86-64)
	CS_ARCH_PPC          // PowerPC architecture
	CS_ARCH_MAX
	CS_ARCH_ALL = 0xFFFF
)

const (
	// Engine Modes
	CS_MODE_LITTLE_ENDIAN = 0       // little endian mode (default mode)
	CS_MODE_ARM           = 0       // 32-bit ARM
	CS_MODE_16            = 1 << 1  // 16-bit mode
	CS_MODE_32            = 1 << 2  // 32-bit mode
	CS_MODE_64            = 1 << 3  // 64-bit mode
	CS_MODE_THUMB         = 1 << 4  // ARM's Thumb mode including Thumb-2
	CS_MODE_MICRO         = 1 << 4  // MicroMips mode (MIPS architecture)
	CS_MODE_N64           = 1 << 5  // Nintendo-64 mode (MIPS architecture)
	CS_MODE_BIG_ENDIAN    = 1 << 31 // big endian mode
)

const (
	// Engine Options types
	CS_OPT_SYNTAX = 1 // Asssembly output syntax
	CS_OPT_DETAIL = 2 // Break down instruction structure into details
	CS_OPT_MODE   = 3 // Change engine's mode at run-time
	CS_OPT_MEM    = 4 // User-defined memory malloc/calloc/free
)

const (
	// Engine Options values
	CS_OPT_OFF              = 0 // Turn OFF an option - default option for CS_OPT_DETAIL.
	CS_OPT_ON               = 3 // Turn ON an option (CS_OPT_DETAIL).
	CS_OPT_SYNTAX_DEFAULT   = 0 // Default asm syntax (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_INTEL     = 1 // X86 Intel asm syntax - default on X86 (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_ATT       = 2 // X86 ATT asm syntax (CS_OPT_SYNTAX).
	CS_OPT_SYNTAX_NOREGNAME = 3 // PPC asm syntax: Prints register name with only number (CS_OPT_SYNTAX)
)

const (
	// All type of errors encountered by Capstone API.
	// These are values returned by cs_errno()
	CS_ERR_OK       = iota // No error: everything was fine
	CS_ERR_MEM             // Out-Of-Memory error: cs_open(), cs_disasm_ex()
	CS_ERR_ARCH            // Unsupported architecture: cs_open()
	CS_ERR_HANDLE          // Invalid handle: cs_op_count(), cs_op_index()
	CS_ERR_CSH             // Invalid csh argument: cs_close(), cs_errno(), cs_option()
	CS_ERR_MODE            // Invalid/unsupported mode: cs_open()
	CS_ERR_OPTION          // Invalid/unsupported option: cs_option()
	CS_ERR_DETAIL          // Information is unavailable because detail option is OFF
	CS_ERR_MEMSETUP        // Dynamic memory management uninitialized (see CS_OPT_MEM)
)
