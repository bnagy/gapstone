****************
Platform: ARM-64
Code:0x21 0x7c 0x02 0x9b 0x21 0x7c 0x00 0x53 0x00 0x40 0x21 0x4b 0xe1 0x0b 0x40 0xb9 0x20 0x04 0x81 0xda 0x20 0x08 0x02 0x8b 
Disasm:
0x2c:	mul	x1, x1, x2
	op_count: 3
		operands[0].type: REG = x1
		operands[1].type: REG = x1
		operands[2].type: REG = x2

0x30:	lsr	w1, w1, #0
	op_count: 3
		operands[0].type: REG = w1
		operands[1].type: REG = w1
		operands[2].type: IMM = 0x0

0x34:	sub	w0, w0, w1, uxtw
	op_count: 3
		operands[0].type: REG = w0
		operands[1].type: REG = w0
		operands[2].type: REG = w1
			Ext: 3

0x38:	ldr	w1, [sp, #8]
	op_count: 2
		operands[0].type: REG = w1
		operands[1].type: MEM
			operands[1].mem.base: REG = sp
			operands[1].mem.disp: 0x8

0x3c:	csneg	x0, x1, x1, eq
	op_count: 3
		operands[0].type: REG = x0
		operands[1].type: REG = x1
		operands[2].type: REG = x1
	Code condition: 1

0x40:	add	x0, x1, x2, lsl #2
	op_count: 3
		operands[0].type: REG = x0
		operands[1].type: REG = x1
		operands[2].type: REG = x2
			Shift: type = 1, value = 2

0x44:

