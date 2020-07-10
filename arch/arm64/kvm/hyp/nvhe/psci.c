// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <linux/compiler.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>

#include <uapi/linux/psci.h>

static void kvm_psci_narrow_to_32bit(struct kvm_vcpu *vcpu)
{
	int i;

	/*
	 * Zero the input registers' upper 32 bits. They will be fully
	 * zeroed on exit, so we're fine changing them in place.
	 */
	for (i = 1; i < 4; i++)
		vcpu_set_reg(vcpu, i, lower_32_bits(vcpu_get_reg(vcpu, i)));
}

int kvm_host_psci_cpu_off(void)
{
	struct arm_smccc_res res;
	arm_smccc_1_1_smc(PSCI_0_2_FN_CPU_OFF, &res);
	/* XXX - check that res.a0 is DENIED */
	return PSCI_RET_DENIED;
}

void __noreturn kvm_host_psci_system_off(void)
{
	struct arm_smccc_res res;
	arm_smccc_1_1_smc(PSCI_0_2_FN_SYSTEM_OFF, &res);
	/* SYSTEM_OFF should never return. */
	for (;;) {}
}

void __noreturn kvm_host_psci_system_reset(void)
{
	struct arm_smccc_res res;
	arm_smccc_1_1_smc(PSCI_0_2_FN_SYSTEM_RESET, &res);
	/* SYSTEM_RESET should never return. */
	for (;;) {}
}

int kvm_host_psci_0_2_call(unsigned long func_id, struct kvm_vcpu *host_vcpu)
{
	switch (func_id) {
	case PSCI_0_2_FN_PSCI_VERSION:
		return KVM_ARM_PSCI_0_2;
	case PSCI_0_2_FN_CPU_OFF:
		return kvm_host_psci_cpu_off();
	case PSCI_0_2_FN_SYSTEM_OFF:
		kvm_host_psci_system_off();
		unreachable();
	case PSCI_0_2_FN_SYSTEM_RESET:
		kvm_host_psci_system_reset();
		unreachable();
	}

	return -EINVAL;
}

int kvm_host_psci_call(struct kvm_vcpu *host_vcpu)
{
	unsigned long func_id = smccc_get_function(host_vcpu);
	unsigned long func_base = func_id & ~PSCI_0_2_FN_ID_MASK;

	/* Early exit if this clearly isn't a PSCI call. */
	if (func_base != PSCI_0_2_FN_BASE && func_base != PSCI_0_2_FN64_BASE)
		return -EINVAL;

	return kvm_host_psci_0_2_call(func_id, host_vcpu);
}
