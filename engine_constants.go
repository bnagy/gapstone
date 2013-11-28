package gapstone

const (
	// Engine Architectures
	CS_ARCH_ARM   = iota // ARM architecture (including Thumb Thumb-2)
	CS_ARCH_ARM64        // ARM-64, also called AArch64
	CS_ARCH_MIPS         // Mips architecture
	CS_ARCH_X86          // X86 architecture (including x86 & x86-64)
	CS_ARCH_MAX
)

const (
	// Engine Modes
	CS_MODE_LITTLE_ENDIAN = 0       // little endian mode (default mode)
	CS_MODE_SYNTAX_INTEL  = 0       // Intel X86 asm syntax (CS_ARCH_X86 architecture)
	CS_MODE_ARM           = 0       // 32-bit ARM
	CS_MODE_16            = 1 << 1  // 16-bit mode
	CS_MODE_32            = 1 << 2  // 32-bit mode
	CS_MODE_64            = 1 << 3  // 64-bit mode
	CS_MODE_THUMB         = 1 << 4  // ARM's Thumb mode including Thumb-2
	CS_MODE_MICRO         = 1 << 4  // MicroMips mode (MIPS architecture)
	CS_MODE_N64           = 1 << 5  // Nintendo-64 mode (MIPS architecture)
	CS_MODE_SYNTAX_ATT    = 1 << 30 // ATT asm syntax (CS_ARCH_X86 architecture)const
	CS_MODE_BIG_ENDIAN    = 1 << 31 // big endian mode
)

const (
	// All type of errors encountered by Capstone API.
	// These are values returned by cs_errno()
	CS_ERR_OK     = iota // No error: everything was fine
	CS_ERR_MEM           // Out-Of-Memory error
	CS_ERR_ARCH          // Unsupported architecture
	CS_ERR_HANDLE        // Invalid handle
	CS_ERR_CSH           // Invalid csh argument
	CS_ERR_MODE          // Invalid/unsupported mode
)
