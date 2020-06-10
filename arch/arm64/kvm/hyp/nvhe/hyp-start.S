/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <linux/linkage.h>

#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/kvm_asm.h>

	/*
	 * x1: HYP stack
	 * x2: HYP vectors
	 */
SYM_CODE_START(__kvm_hyp_start)
	/* Set the stack and new vectors */
	mov	sp, x1
	msr	vbar_el2, x2

	/* Hello, World! */
	eret
SYM_CODE_END(__kvm_hyp_start)
