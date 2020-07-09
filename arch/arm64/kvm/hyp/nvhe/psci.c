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
