// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google LLC
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <kvm/arm_hypercalls.h>
#include <linux/arm-smccc.h>
#include <linux/psci.h>
#include <kvm/arm_psci.h>
#include <uapi/linux/psci.h>

/* Config options set by the host. */
u32 kvm_host_psci_version = PSCI_VERSION(0, 0);
u32 kvm_host_psci_function_id[PSCI_FN_MAX];

static u64 get_psci_func_id(struct kvm_cpu_context *host_ctxt)
{
	return host_ctxt->regs.regs[0];
}

static bool is_psci_0_1_call(u64 func_id)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(kvm_host_psci_function_id); ++i) {
		if (func_id == kvm_host_psci_function_id[i])
			return true;
	}
	return false;
}

static bool is_psci_0_2_fn32_call(u64 func_id)
{
	return (func_id & ~PSCI_0_2_FN_ID_MASK) == PSCI_0_2_FN_BASE;
}

static bool is_psci_0_2_fn64_call(u64 func_id)
{
	return (func_id & ~PSCI_0_2_FN_ID_MASK) == PSCI_0_2_FN64_BASE;
}

static void psci_narrow_to_32bit(struct kvm_cpu_context *cpu_ctxt)
{
	int i;

	/*
	 * Zero the input registers' upper 32 bits. They will be fully
	 * zeroed on exit, so we're fine changing them in place.
	 */
	for (i = 1; i < 4; i++)
		cpu_ctxt->regs.regs[i] = lower_32_bits(cpu_ctxt->regs.regs[i]);
}

static unsigned long psci_0_1_handler(struct kvm_cpu_context *host_ctxt)
{
	return PSCI_RET_NOT_SUPPORTED;
}

static unsigned long psci_0_2_handler(struct kvm_cpu_context *host_ctxt)
{
	u64 func_id = get_psci_func_id(host_ctxt);

	if (is_psci_0_2_fn32_call(func_id))
		psci_narrow_to_32bit(host_ctxt);

	switch (func_id) {
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

static unsigned long psci_1_0_handler(struct kvm_cpu_context *host_ctxt)
{
	int ret;

	ret = psci_0_2_handler(host_ctxt);
	if (ret != PSCI_RET_NOT_SUPPORTED)
		return ret;

	/*
	 * psci_0_2_handler already narrowed arguments of 32-bit calls,
	 * no need to do that again here.
	 */

	switch (get_psci_func_id(host_ctxt)) {
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

bool kvm_host_is_psci_call(struct kvm_cpu_context *host_ctxt)
{
	u64 func_id = get_psci_func_id(host_ctxt);

	if (kvm_host_psci_version == PSCI_VERSION(0, 0))
		return false;
	else if (kvm_host_psci_version == PSCI_VERSION(0, 1))
		return is_psci_0_1_call(func_id);
	else
		return is_psci_0_2_fn32_call(func_id) || is_psci_0_2_fn64_call(func_id);
}

void kvm_host_psci_handler(struct kvm_cpu_context *host_ctxt)
{
	unsigned long ret;

	if (kvm_host_psci_version == PSCI_VERSION(0, 1))
		ret = psci_0_1_handler(host_ctxt);
	else if (kvm_host_psci_version == PSCI_VERSION(0, 2))
		ret = psci_0_2_handler(host_ctxt);
	else if (PSCI_VERSION_MAJOR(kvm_host_psci_version) >= 1)
		ret = psci_1_0_handler(host_ctxt);
	else
		ret = PSCI_RET_NOT_SUPPORTED;

	host_ctxt->regs.regs[0] = ret;
	host_ctxt->regs.regs[1] = 0;
	host_ctxt->regs.regs[2] = 0;
	host_ctxt->regs.regs[3] = 0;
}
