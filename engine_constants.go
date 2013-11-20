package gapstone

const CS_ARCH_ARM = 0   // ARM architecture (including Thumb Thumb-2)
const CS_ARCH_ARM64 = 1 // ARM-64, also called AArch64
const CS_ARCH_MIPS = 2  // Mips architecture
const CS_ARCH_X86 = 3   // X86 architecture (including x86 & x86-64)
const CS_ARCH_MAX = 4

const CS_MODE_LITTLE_ENDIAN = 0    // little endian mode (default mode)
const CS_MODE_SYNTAX_INTEL = 0     // Intel X86 asm syntax (CS_ARCH_X86 architecture)
const CS_MODE_ARM = 0              // 32-bit ARM
const CS_MODE_16 = 1 << 1          // 16-bit mode
const CS_MODE_32 = 1 << 2          // 32-bit mode
const CS_MODE_64 = 1 << 3          // 64-bit mode
const CS_MODE_THUMB = 1 << 4       // ARM's Thumb mode including Thumb-2
const CS_MODE_MICRO = 1 << 4       // MicroMips mode (MIPS architecture)
const CS_MODE_N64 = 1 << 5         // Nintendo-64 mode (MIPS architecture)
const CS_MODE_SYNTAX_ATT = 1 << 30 // ATT asm syntax (CS_ARCH_X86 architecture)const
const CS_MODE_BIG_ENDIAN = 1 << 31 // big endian mode
