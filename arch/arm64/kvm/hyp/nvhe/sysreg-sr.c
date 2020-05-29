// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012-2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/kprobes.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>

#include "../sysreg-sr.h"

/*
 * Non-VHE: Both host and guest must save everything.
 */

/*
 * This is a copy of the same per-cpu symbol in kernel proper (used by VHE).
 * Giving it the same name means ensures VHE/nVHE source-level compatibility.
 * Source files compiled for nVHE will link against this copy.
 */
#ifdef CONFIG_ARM64_SSBD
DEFINE_PER_CPU_READ_MOSTLY(u64, arm64_ssbd_callback_required);
#endif

void __sysreg_save_state_nvhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_save_el1_state(ctxt);
	__sysreg_save_common_state(ctxt);
	__sysreg_save_user_state(ctxt);
	__sysreg_save_el2_return_state(ctxt);
}

void __sysreg_restore_state_nvhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_restore_el1_state(ctxt);
	__sysreg_restore_common_state(ctxt);
	__sysreg_restore_user_state(ctxt);
	__sysreg_restore_el2_return_state(ctxt);
}

void __sysreg32_save_state(struct kvm_vcpu *vcpu)
{
	___sysreg32_save_state(vcpu);
}

void __sysreg32_restore_state(struct kvm_vcpu *vcpu)
{
	___sysreg32_restore_state(vcpu);
}

void __kvm_enable_ssbs(void)
{
	u64 tmp;

	asm volatile(
	"mrs	%0, sctlr_el2\n"
	"orr	%0, %0, %1\n"
	"msr	sctlr_el2, %0"
	: "=&r" (tmp) : "L" (SCTLR_ELx_DSSBS));
}

void __kvm_set_ssbd_callback_required(void)
{
#ifdef CONFIG_ARM64_SSBD
	__this_cpu_write(arm64_ssbd_callback_required, 1);
#endif
}
