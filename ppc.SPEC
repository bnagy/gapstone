****************
Platform: PPC-64
Code:0x80 0x20 0x00 0x00 0x80 0x3f 0x00 0x00 0x10 0x43 0x23 0x0e 0xd0 0x44 0x00 0x80 0x4c 0x43 0x22 0x02 0x2d 0x03 0x00 0x80 0x7c 0x43 0x20 0x14 0x7c 0x43 0x20 0x93 0x4f 0x20 0x00 0x21 0x4c 0xc8 0x00 0x21 
Disasm:
0x1000:	lwz	r1, (0)
	op_count: 2
		operands[0].type: REG = r1
		operands[1].type: MEM
			operands[1].mem.base: REG = cr0

0x1004:	lwz	r1, (r31)
	op_count: 2
		operands[0].type: REG = r1
		operands[1].type: MEM
			operands[1].mem.base: REG = r31

0x1008:	vpkpx	v2, v3, v4
	op_count: 3
		operands[0].type: REG = v2
		operands[1].type: REG = v3
		operands[2].type: REG = v4

0x100c:	stfs	f2, 0x80(r4)
	op_count: 2
		operands[0].type: REG = f2
		operands[1].type: MEM
			operands[1].mem.base: REG = r4
			operands[1].mem.disp: 0x80

0x1010:	crand	2, 3, 4
	op_count: 3
		operands[0].type: REG = cr2
		operands[1].type: REG = cr3
		operands[2].type: REG = cr4

0x1014:	cmpwi	cr2, r3, 0x80
	op_count: 3
		operands[0].type: REG = cr2
		operands[1].type: REG = r3
		operands[2].type: IMM = 0x80

0x1018:	addc	r2, r3, r4
	op_count: 3
		operands[0].type: REG = r2
		operands[1].type: REG = r3
		operands[2].type: REG = r4

0x101c:	mulhd.	r2, r3, r4
	op_count: 3
		operands[0].type: REG = r2
		operands[1].type: REG = r3
		operands[2].type: REG = r4
	Update-CR0: True

0x1020:	bdnzlrl+	
	Branch hint: 1

0x1024:	bclrl	6, 8, 0
	op_count: 3
		operands[0].type: IMM = 0x6
		operands[1].type: REG = cr8
		operands[2].type: IMM = 0x0

0x1028:

