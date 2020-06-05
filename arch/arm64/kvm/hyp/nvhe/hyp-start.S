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

	/* Hello, World! */
	eret
SYM_CODE_END(__kvm_hyp_start)
