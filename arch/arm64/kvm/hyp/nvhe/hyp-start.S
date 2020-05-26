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

	/* Save some of the host's state so it can be restored */
	adr_this_cpu		x0, kvm_host_vcpu, x1
	add			x0, x0, #VCPU_CONTEXT
	save_callee_saved_regs	x0
	save_sp_el0		x0, x1

	b	kvm_hyp_main
SYM_CODE_END(__kvm_hyp_start)
