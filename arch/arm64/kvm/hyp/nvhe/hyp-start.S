/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <linux/linkage.h>

#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/kvm_asm.h>

SYM_CODE_START(__kvm_hyp_start)
	/* Set the stack and new vectors */
	adr_this_cpu x0, kvm_nvhe_hyp_params, x1
	ldr	x1, [x0, #HYP_PARAMS_STACK]
	mov	sp, x1
	ldr	x1, [x0, #HYP_PARAMS_VECTOR]
	msr	vbar_el2, x1

	/*
	 * The host has already saved off the caller-saved registers
	 * prior to executing the hvc instruction and we can rely on the
	 * compiler to save/restore the callee-saved registers once we're
	 * running C functions. We just need to be careful with lr,
	 * since it's clobbered by the BL instruction, so preserve it
	 * across the call into C.
	 */
	str	lr, [sp, #-16]!
	bl	kvm_hyp_main
	ldr	lr, [sp], #16

	/* Hello, World! */
	eret
SYM_CODE_END(__kvm_hyp_start)
