****************
Platform: X86 16bit (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 
Disasm:
0x1000:	lea		cx, dword ptr [si + 0x32] // insn-ID: 296, insn-mnem: lea
0x1003:	or		byte ptr [bx + di], al // insn-ID: 306, insn-mnem: or
	Implicit registers modified: flags 
0x1005:	fadd		dword ptr [bx + di + 0x34c6] // insn-ID: 15, insn-mnem: fadd
	Implicit registers modified: fpsw 
0x1009:	adc		al, byte ptr [bx + si] // insn-ID: 6, insn-mnem: adc
	Implicit registers read: flags 
	Implicit registers modified: flags 
0x100b:

****************
Platform: X86 32bit (ATT syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 
Disasm:
0x1000:	leal		dword ptr 8(%edx, %esi), %ecx // insn-ID: 296, insn-mnem: lea
	This instruction belongs to groups: 33 
0x1004:	addl		%ebx, %eax // insn-ID: 8, insn-mnem: add
	Implicit registers modified: eflags 
0x1006:	addl		$0x1234, %esi // insn-ID: 8, insn-mnem: add
	Implicit registers modified: eflags 
0x100c:

****************
Platform: X86 32 (Intel syntax)
Code: 0x8d 0x4c 0x32 0x08 0x01 0xd8 0x81 0xc6 0x34 0x12 0x00 0x00 
Disasm:
0x1000:	lea		ecx, dword ptr [edx + esi + 8] // insn-ID: 296, insn-mnem: lea
	This instruction belongs to groups: 33 
0x1004:	add		eax, ebx // insn-ID: 8, insn-mnem: add
	Implicit registers modified: eflags 
0x1006:	add		esi, 0x1234 // insn-ID: 8, insn-mnem: add
	Implicit registers modified: eflags 
0x100c:

****************
Platform: X86 64 (Intel syntax)
Code: 0x55 0x48 0x8b 0x05 0xb8 0x13 0x00 0x00 
Disasm:
0x1000:	push		rbp // insn-ID: 562, insn-mnem: push
	Implicit registers read: rsp 
	Implicit registers modified: rsp 
	This instruction belongs to groups: 17 
0x1001:	mov		rax, qword ptr [rip + 0x13b8] // insn-ID: 424, insn-mnem: mov
0x1008:

****************
Platform: ARM
Code: 0xed 0xff 0xff 0xeb 0x04 0xe0 0x2d 0xe5 0x00 0x00 0x00 0x00 0xe0 0x83 0x22 0xe5 0xf1 0x02 0x03 0x0e 0x00 0x00 0xa0 0xe3 0x02 0x30 0xc1 0xe7 0x00 0x00 0x53 0xe3 
Disasm:
0x1000:	bl		#-0x4c // insn-ID: 13, insn-mnem: bl
	Implicit registers read: sp 
	Implicit registers modified: lr 
	This instruction belongs to groups: 20 
0x1004:	str		lr, [sp, #-0x4]! // insn-ID: 212, insn-mnem: str
	This instruction belongs to groups: 20 
0x1008:	andeq		r0, r0, r0 // insn-ID: 8, insn-mnem: and
	This instruction belongs to groups: 20 
0x100c:	str		r8, [r2, #-0x3e0]! // insn-ID: 212, insn-mnem: str
	This instruction belongs to groups: 20 
0x1010:	mcreq		p2, #0, r0, c3, c1, #7 // insn-ID: 74, insn-mnem: mcr
	This instruction belongs to groups: 20 
0x1014:	mov		r0, #0 // insn-ID: 80, insn-mnem: mov
	This instruction belongs to groups: 20 
0x1018:	strb		r3, [r1, r2] // insn-ID: 203, insn-mnem: strb
	This instruction belongs to groups: 20 
0x101c:	cmp		r3, #0 // insn-ID: 23, insn-mnem: cmp
	Implicit registers modified: cpsr 
	This instruction belongs to groups: 20 
0x1020:

****************
Platform: THUMB-2
Code: 0x4f 0xf0 0x00 0x01 0xbd 0xe8 0x00 0x88 0xd1 0xe8 0x00 0xf0 
Disasm:
0x1000:	mov.w		r1, #0 // insn-ID: 80, insn-mnem: mov
	This instruction belongs to groups: 25 
0x1004:	pop.w		{fp, pc} // insn-ID: 57, insn-mnem: ldm
	This instruction belongs to groups: 25 
0x1008:	tbb		[r1, r0] // insn-ID: 415, insn-mnem: tbb
	This instruction belongs to groups: 25 32 
0x100c:

****************
Platform: ARM: Cortex-A15 + NEON
Code: 0x10 0xf1 0x10 0xe7 0x11 0xf2 0x31 0xe7 0xdc 0xa1 0x2e 0xf3 0xe8 0x4e 0x62 0xf3 
Disasm:
0x1000:	sdiv		r0, r0, r1 // insn-ID: 122, insn-mnem: sdiv
	This instruction belongs to groups: 20 
0x1004:	udiv		r1, r1, r2 // insn-ID: 230, insn-mnem: udiv
	This instruction belongs to groups: 20 
0x1008:	vbit		q5, q15, q6 // insn-ID: 273, insn-mnem: vbit
	This instruction belongs to groups: 6 
0x100c:	vcgt.f32		q10, q9, q12 // insn-ID: 277, insn-mnem: vcgt
	This instruction belongs to groups: 6 
0x1010:

****************
Platform: THUMB
Code: 0x70 0x47 0xeb 0x46 0x83 0xb0 0xc9 0x68 
Disasm:
0x1000:	bx		lr // insn-ID: 15, insn-mnem: bx
	This instruction belongs to groups: 23 32 
0x1002:	mov		fp, sp // insn-ID: 80, insn-mnem: mov
	This instruction belongs to groups: 23 24 
0x1004:	sub		sp, #0xc // insn-ID: 213, insn-mnem: sub
	This instruction belongs to groups: 23 24 
0x1006:	ldr		r1, [r1, #0xc] // insn-ID: 73, insn-mnem: ldr
	This instruction belongs to groups: 23 24 
0x1008:

****************
Platform: MIPS-32 (Big-endian)
Code: 0x0c 0x10 0x00 0x97 0x00 0x00 0x00 0x00 0x24 0x02 0x00 0x0c 0x8f 0xa2 0x00 0x00 0x34 0x21 0x34 0x56 
Disasm:
0x1000:	jal		0x40025c // insn-ID: 244, insn-mnem: jal
	Implicit registers modified: ra 
	This instruction belongs to groups: 10 
0x1004:	nop		 // insn-ID: 454, insn-mnem: nop
	This instruction belongs to groups: 10 
0x1008:	addiu		$v0, $zero, 0xc // insn-ID: 20, insn-mnem: addiu
	This instruction belongs to groups: 10 
0x100c:	lw		$v0, ($sp) // insn-ID: 267, insn-mnem: lw
	This instruction belongs to groups: 10 
0x1010:	ori		$at, $at, 0x3456 // insn-ID: 339, insn-mnem: ori
	This instruction belongs to groups: 10 
0x1014:

****************
Platform: MIPS-64-EL (Little-endian)
Code: 0x56 0x34 0x21 0x34 0xc2 0x17 0x01 0x00 
Disasm:
0x1000:	ori		$at, $at, 0x3456 // insn-ID: 339, insn-mnem: ori
	This instruction belongs to groups: 10 
0x1004:	srl		$v0, $at, 0x1f // insn-ID: 406, insn-mnem: srl
	This instruction belongs to groups: 10 
0x1008:

****************
Platform: ARM-64
Code: 0x21 0x7c 0x02 0x9b 0x21 0x7c 0x00 0x53 0x00 0x40 0x21 0x4b 0xe1 0x0b 0x40 0xb9 0x10 0x20 0x21 0x1e 
Disasm:
0x1000:	mul		x1, x1, x2 // insn-ID: 212, insn-mnem: mul
0x1004:	lsr		w1, w1, #0 // insn-ID: 201, insn-mnem: lsr
0x1008:	sub		w0, w0, w1, uxtw // insn-ID: 349, insn-mnem: sub
0x100c:	ldr		w1, [sp, #8] // insn-ID: 170, insn-mnem: ldr
0x1010:	fcmpe		s0, s1 // insn-ID: 86, insn-mnem: fcmpe
	Implicit registers modified: nzcv 
	This instruction belongs to groups: 2 
0x1014:

****************
Platform: PPC-64
Code: 0x80 0x20 0x00 0x00 0x80 0x3f 0x00 0x00 0x10 0x43 0x23 0x0e 0xd0 0x44 0x00 0x80 0x4c 0x43 0x22 0x02 0x2d 0x03 0x00 0x80 0x7c 0x43 0x20 0x14 0x7c 0x43 0x20 0x93 0x4f 0x20 0x00 0x21 0x4c 0xc8 0x00 0x21 
Disasm:
0x1000:	lwz		r1, (0) // insn-ID: 167, insn-mnem: lwz
0x1004:	lwz		r1, (r31) // insn-ID: 167, insn-mnem: lwz
0x1008:	vpkpx		v2, v3, v4 // insn-ID: 363, insn-mnem: vpkpx
	This instruction belongs to groups: 1 
0x100c:	stfs		f2, 0x80(r4) // insn-ID: 247, insn-mnem: stfs
0x1010:	crand		2, 3, 4 // insn-ID: 46, insn-mnem: crand
0x1014:	cmpwi		cr2, r3, 0x80 // insn-ID: 41, insn-mnem: cmpwi
0x1018:	addc		r2, r3, r4 // insn-ID: 2, insn-mnem: addc
	Implicit registers modified: ca 
0x101c:	mulhd.		r2, r3, r4 // insn-ID: 193, insn-mnem: mulhd
	Implicit registers modified: cr0 
0x1020:	bdnzlrl+		 // insn-ID: 23, insn-mnem: bdnzlrl
	Implicit registers read: ctr lr rm 
	Implicit registers modified: ctr 
0x1024:	bclrl		6, 8, 0 // insn-ID: 435, insn-mnem: bclrl
	Implicit registers read: ctr lr rm 
	Implicit registers modified: lr ctr 
0x1028:

****************
Platform: Sparc
Code: 0x80 0xa0 0x40 0x02 0x85 0xc2 0x60 0x08 0x85 0xe8 0x20 0x01 0x81 0xe8 0x00 0x00 0x90 0x10 0x20 0x01 0xd5 0xf6 0x10 0x16 0x21 0x00 0x00 0x0a 0x86 0x00 0x40 0x02 0x01 0x00 0x00 0x00 0x12 0xbf 0xff 0xff 0x10 0xbf 0xff 0xff 0xa0 0x02 0x00 0x09 0x0d 0xbf 0xff 0xff 0xd4 0x20 0x60 0x00 0xd4 0x4e 0x00 0x16 0x2a 0xc2 0x80 0x03 
Disasm:
0x1000:	cmp		%g1, %g2 // insn-ID: 34, insn-mnem: cmp
	Implicit registers modified: icc 
0x1004:	jmpl		%o1+8, %g2 // insn-ID: 195, insn-mnem: jmpl
0x1008:	restore		%g0, 1, %g2 // insn-ID: 227, insn-mnem: restore
0x100c:	restore		 // insn-ID: 227, insn-mnem: restore
0x1010:	or		%g0, 1, %o0 // insn-ID: 222, insn-mnem: or
0x1014:	casx		[%i0], %l6, %o2 // insn-ID: 29, insn-mnem: casx
	This instruction belongs to groups: 7 
0x1018:	sethi		0xa, %l0 // insn-ID: 233, insn-mnem: sethi
0x101c:	add		%g1, %g2, %g3 // insn-ID: 6, insn-mnem: add
0x1020:	nop		 // insn-ID: 218, insn-mnem: nop
0x1024:	bne		0x3fffff // insn-ID: 17, insn-mnem: b
	Implicit registers read: icc 
	This instruction belongs to groups: 8 
0x1028:	ba		0x3fffff // insn-ID: 16, insn-mnem: ba
	This instruction belongs to groups: 8 
0x102c:	add		%o0, %o1, %l0 // insn-ID: 6, insn-mnem: add
0x1030:	fbg		0x3fffff // insn-ID: 20, insn-mnem: fb
	Implicit registers read: fcc0 
	This instruction belongs to groups: 8 
0x1034:	st		%o2, [%g1] // insn-ID: 247, insn-mnem: st
0x1038:	ldsb		[%i0+%l6], %o2 // insn-ID: 199, insn-mnem: ldsb
0x103c:	brnz,a,pn		%o2, 3 // insn-ID: 25, insn-mnem: brnz
	This instruction belongs to groups: 7 8 
0x1040:

****************
Platform: SparcV9
Code: 0x81 0xa8 0x0a 0x24 0x89 0xa0 0x10 0x20 0x89 0xa0 0x1a 0x60 0x89 0xa0 0x00 0xe0 
Disasm:
0x1000:	fcmps		%fcc0, %f0, %f4 // insn-ID: 71, insn-mnem: fcmps
0x1004:	fstox		%f0, %f4 // insn-ID: 182, insn-mnem: fstox
	This instruction belongs to groups: 7 
0x1008:	fqtoi		%f0, %f4 // insn-ID: 160, insn-mnem: fqtoi
	This instruction belongs to groups: 1 
0x100c:	fnegq		%f0, %f4 // insn-ID: 128, insn-mnem: fnegq
	This instruction belongs to groups: 2 
0x1010:

****************
Platform: SystemZ
Code: 0xed 0x00 0x00 0x00 0x00 0x1a 0x5a 0x0f 0x1f 0xff 0xc2 0x09 0x80 0x00 0x00 0x00 0x07 0xf7 0xeb 0x2a 0xff 0xff 0x7f 0x57 0xe3 0x01 0xff 0xff 0x7f 0x57 0xeb 0x00 0xf0 0x00 0x00 0x24 0xb2 0x4f 0x00 0x78 
Disasm:
0x1000:	adb		%f0, 0 // insn-ID: 2, insn-mnem: adb
	Implicit registers modified: cc 
0x1006:	a		%r0, 0xfff(%r15, %r1) // insn-ID: 1, insn-mnem: a
	Implicit registers modified: cc 
0x100a:	afi		%r0, -0x80000000 // insn-ID: 6, insn-mnem: afi
	Implicit registers modified: cc 
0x1010:	br		%r7 // insn-ID: 283, insn-mnem: br
	This instruction belongs to groups: 6 
0x1012:	xiy		0x7ffff(%r15), 0x2a // insn-ID: 675, insn-mnem: xiy
	Implicit registers modified: cc 
0x1018:	xy		%r0, 0x7ffff(%r1, %r15) // insn-ID: 678, insn-mnem: xy
	Implicit registers modified: cc 
0x101e:	stmg		%r0, %r0, 0(%r15) // insn-ID: 654, insn-mnem: stmg
0x1024:	ear		%r7, %a8 // insn-ID: 383, insn-mnem: ear
0x1028:

