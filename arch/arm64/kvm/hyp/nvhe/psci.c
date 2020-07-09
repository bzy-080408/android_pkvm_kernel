// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#include <kvm/arm_hypercalls.h>

#include <uapi/linux/psci.h>

int kvm_host_psci_call(struct kvm_vcpu *host_vcpu)
{
	bool is_32bit;
	int ret = -EINVAL;
	unsigned long fn_id = smccc_get_function(host_vcpu);
	unsigned long fn_base = fn_id & ~PSCI_0_2_FN_ID_MASK;

	if (fn_base == PSCI_0_2_FN_BASE)
		is_32bit = true;
	else if (fn_base == PSCI_0_2_FN64_BASE)
		is_32bit = false;
	else
		return ret;

	return ret;
}
