Frag-0: 1
Frag-1: 3
Frag-0: 1
Frag-1: 0
Frag-2: 0
Frag-3: 1
Frag-4: 0
Frag-5: 0
Frag-0: 1
Frag-1: 0
Frag-2: 6
Frag-0: 1
Frag-1: 0
Frag-2: 0
Frag-3: 1
Frag-4: 2
Frag-5: 0
****************
Platform: MIPS-32 (Big-endian)
Code:0x0c 0x10 0x00 0x97 0x00 0x00 0x00 0x00 0x24 0x02 0x00 0x0c 0x8f 0xa2 0x00 0x00 0x34 0x21 0x34 0x56 
Disasm:
0x1000:	jal	0x40025c
	op_count: 1
		operands[0].type: IMM = 0x40025c

0x1004:	nop	

0x1008:	addiu	$v0, $zero, 0xc
	op_count: 3
		operands[0].type: REG = v0
		operands[1].type: REG = zero
		operands[2].type: IMM = 0xc

0x100c:	lw	$v0, ($sp)
	op_count: 2
		operands[0].type: REG = v0
		operands[1].type: MEM
			operands[1].mem.base: REG = sp

0x1010:	ori	$at, $at, 0x3456
	op_count: 3
		operands[0].type: REG = at
		operands[1].type: REG = at
		operands[2].type: IMM = 0x3456

0x1014:

Frag-0: 1
Frag-1: 0
Frag-2: 0
Frag-3: 1
Frag-4: 2
Frag-5: 0
Frag-0: 1
Frag-1: 0
Frag-2: 0
Frag-3: 1
Frag-4: 2
Frag-5: 0
****************
Platform: MIPS-64-EL (Little-endian)
Code:0x56 0x34 0x21 0x34 0xc2 0x17 0x01 0x00 
Disasm:
0x1000:	ori	$at, $at, 0x3456
	op_count: 3
		operands[0].type: REG = at
		operands[1].type: REG = at
		operands[2].type: IMM = 0x3456

0x1004:	srl	$v0, $at, 0x1f
	op_count: 3
		operands[0].type: REG = v0
		operands[1].type: REG = at
		operands[2].type: IMM = 0x1f

0x1008:

