****************
Platform: M68K
Code: 0xd4 0x40 0x87 0x5a 0x4e 0x71 0x02 0xb4 0xc0 0xde 0xc0 0xde 0x5c 0x00 0x1d 0x80 0x71 0x12 0x01 0x23 0xf2 0x3c 0x44 0x22 0x40 0x49 0x0e 0x56 0x54 0xc5 0xf2 0x3c 0x44 0x00 0x44 0x7a 0x00 0x00 0xf2 0x00 0x0a 0x28 0x4e 0xb9 0x00 0x00 0x00 0x12 0x4e 0x75 
Disasm:
0x1000:	add.w	d0, d2
	op_count: 2
	groups_count: 0
		operands[0].type: REG = d0
		operands[1].type: REG = d2

0x1002:	or.w	d3, (a2)+
	op_count: 2
	groups_count: 0
		operands[0].type: REG = d3
		operands[1].type: MEM
			operands[1].mem.base: REG = a2
		address mode: Register Indirect - Address with Postincrement

0x1004:	nop	
	groups_count: 0

0x1006:	andi.l	#$c0dec0de, (a4, d5.l * 4)
	op_count: 2
	groups_count: 0
		operands[0].type: IMM = 0xc0dec0de
		operands[1].type: MEM
			operands[1].mem.base: REG = a4
			operands[1].mem.index: REG = d5
			operands[1].mem.index: size = l
			operands[1].mem.scale: 4
		address mode: Address Register Indirect With Index - Base displacement

0x100e:	move.b	d0, ([a6, d7.w], $123)
	op_count: 2
	groups_count: 0
		operands[0].type: REG = d0
		operands[1].type: MEM
			operands[1].mem.base: REG = a6
			operands[1].mem.index: REG = d7
			operands[1].mem.index: size = w
		address mode: Memory indirect - Preindex

0x1014:	fadd.s	#3.141500, fp0
	op_count: 2
	groups_count: 0
		operands[0].type: FP_SINGLE
			operands[0].simm: 3.141500
		operands[1].type: REG = fp0

0x101c:	scc.b	d5
	op_count: 1
	groups_count: 0
		operands[0].type: REG = d5

0x101e:	fmove.s	#1000.000000, fp0
	op_count: 2
	groups_count: 0
		operands[0].type: FP_SINGLE
			operands[0].simm: 1000.000000
		operands[1].type: REG = fp0

0x1026:	fsub	fp2, fp4
	op_count: 2
	groups_count: 0
		operands[0].type: REG = fp2
		operands[1].type: REG = fp4

0x102a:	jsr	$12.l
	op_count: 1
	groups_count: 1
		operands[0].type: MEM
			operands[0].mem.base: REG = fp1
		address mode: Absolute Data Addressing  - Long

0x1030:	rts	
	groups_count: 1

0x1032:

