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
	 * Save the host's general purpose registers so they can be restored
	 * when entering back into the host. SMCCC only permits x0-3 to be
	 * modified and they will be set to return values before entering back
	 * into the host so have not had their original values saved.
	 */
	adr_this_cpu x0, kvm_host_vcpu, x1
	add	x0, x0, #VCPU_CONTEXT

	/* Store the host regs x4-x17 */
	stp	x4, x5,   [x0, #CPU_XREG_OFFSET(4)]
	stp	x6, x7,   [x0, #CPU_XREG_OFFSET(6)]
	stp	x8, x9,   [x0, #CPU_XREG_OFFSET(8)]
	stp	x10, x11, [x0, #CPU_XREG_OFFSET(10)]
	stp	x12, x13, [x0, #CPU_XREG_OFFSET(12)]
	stp	x14, x15, [x0, #CPU_XREG_OFFSET(14)]
	stp	x16, x17, [x0, #CPU_XREG_OFFSET(16)]

	/* Store the host regs x18-x29, lr */
	save_callee_saved_regs x0

	/* Store the host's sp_el0 */
	save_sp_el0 x0, x1

	b	kvm_hyp_main
SYM_CODE_END(__kvm_hyp_start)
