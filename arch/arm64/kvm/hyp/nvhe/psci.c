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

#include <nvhe/memory.h>
#include <nvhe/spinlock.h>

#define INVALID_CPU_ID UINT_MAX

/* Config options set by the host. */
u32 kvm_host_psci_version = PSCI_VERSION(0, 0);
u32 kvm_host_psci_function_id[PSCI_FN_MAX];
u32 kvm_host_psci_cpu_suspend_feature;

enum kvm_host_cpu_power_state {
	KVM_HOST_CPU_POWER_OFF = 0,
	KVM_HOST_CPU_POWER_PENDING_ON,
	KVM_HOST_CPU_POWER_ON,
};

struct kvm_host_psci_cpu {
	nvhe_spinlock_t lock;
	enum kvm_host_cpu_power_state power_state;

	struct vcpu_reset_state reset_state;
};

static DEFINE_PER_CPU(struct kvm_host_psci_cpu, kvm_psci_host_cpu) =
	(struct kvm_host_psci_cpu){
		.lock = NVHE_SPIN_LOCK_INIT,
		.power_state = KVM_HOST_CPU_POWER_OFF,
	};

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

static unsigned long psci_call(unsigned long fn, unsigned long arg0,
			       unsigned long arg1, unsigned long arg2)
{
	struct arm_smccc_res res;
	arm_smccc_1_1_smc(fn, arg0, arg1, arg2, &res);
	return res.a0;
}

static bool psci_has_ext_power_state(void)
{
	return kvm_host_psci_cpu_suspend_feature & PSCI_1_0_FEATURES_CPU_SUSPEND_PF_MASK;
}

static bool psci_power_state_loses_context(u32 state)
{
	const u32 mask = psci_has_ext_power_state() ?
					PSCI_1_0_EXT_POWER_STATE_TYPE_MASK :
					PSCI_0_2_POWER_STATE_TYPE_MASK;

	return state & mask;
}

static unsigned int find_cpu_id(u64 mpidr)
{
	unsigned int i;

	if (mpidr != INVALID_HWID) {
		for (i = 0; i < nr_cpu_ids; i++) {
			if (cpu_logical_map(i) == mpidr)
				return i;
		}
	}

	return INVALID_CPU_ID;
}

static phys_addr_t cpu_entry_pa(void)
{
	extern char __kvm_hyp_cpu_entry[];
	unsigned long kern_va;

	asm volatile("ldr %0, =%1" : "=r" (kern_va) : "S" (__kvm_hyp_cpu_entry));
	return kern_va - kimage_voffset;
}

static unsigned int psci_version(void)
{
	return (unsigned int)psci_call(PSCI_0_2_FN_PSCI_VERSION, 0, 0, 0);
}

static int psci_features(struct kvm_cpu_context *host_ctxt)
{
	u32 psci_func_id = (u32)host_ctxt->regs.regs[1];

	return (int)psci_call(PSCI_1_0_FN_PSCI_FEATURES, psci_func_id, 0, 0);
}

static int psci_cpu_suspend(struct kvm_cpu_context *host_ctxt)
{
	u64 state = host_ctxt->regs.regs[1];
	unsigned long pc = host_ctxt->regs.regs[1];
	unsigned long r0 = host_ctxt->regs.regs[2];
	struct kvm_host_psci_cpu *host_cpu = this_cpu_ptr(&kvm_psci_host_cpu);
	struct kvm_nvhe_init_params *init_params = this_cpu_ptr(&kvm_init_params);
	int ret;

	if (!psci_power_state_loses_context(state)) {
		// Resuming from this state has the same semantics as WFI.
		return (int)psci_call(PSCI_0_2_FN64_CPU_SUSPEND, 0, 0, 0);
	}

	/* If successful, resuming from this state has the same semantics as CPU_ON. */
	nvhe_spin_lock(&host_cpu->lock);
	host_cpu->reset_state = (struct vcpu_reset_state){
		.pc = pc,
		.r0 = r0,
		.reset = true,
	};
	nvhe_spin_unlock(&host_cpu->lock);

	ret = (int)psci_call(kvm_host_psci_function_id[PSCI_FN_CPU_SUSPEND],
			     state,
			     cpu_entry_pa(),
			     __hyp_pa(init_params));

	nvhe_spin_lock(&host_cpu->lock);
	host_cpu->reset_state = (struct vcpu_reset_state){
		.reset = false,
	};
	nvhe_spin_unlock(&host_cpu->lock);

	return ret;
}

static int psci_cpu_off(struct kvm_cpu_context *host_ctxt)
{
	u64 func_id = get_psci_func_id(host_ctxt);
	u32 state = host_ctxt->regs.regs[1];
	struct kvm_host_psci_cpu *host_cpu = this_cpu_ptr(&kvm_psci_host_cpu);
	int ret;

	nvhe_spin_lock(&host_cpu->lock);
	host_cpu->power_state = KVM_HOST_CPU_POWER_OFF;
	nvhe_spin_unlock(&host_cpu->lock);

	ret = psci_call(func_id, state, 0, 0);

	nvhe_spin_lock(&host_cpu->lock);
	host_cpu->power_state = KVM_HOST_CPU_POWER_ON;
	nvhe_spin_unlock(&host_cpu->lock);
	return ret;
}

static int psci_cpu_on(struct kvm_cpu_context *host_ctxt)
{
	u64 mpidr = host_ctxt->regs.regs[1] & MPIDR_HWID_BITMASK;
	unsigned long pc = host_ctxt->regs.regs[2];
	unsigned long r0 = host_ctxt->regs.regs[3];
	unsigned int target_cpu_id;
	struct kvm_host_psci_cpu *target_cpu;
	struct kvm_nvhe_init_params *target_init_params;
	int ret;

	target_cpu_id = find_cpu_id(mpidr);
	if (target_cpu_id == INVALID_CPU_ID)
		return PSCI_RET_INVALID_PARAMS;

	target_cpu = per_cpu_ptr(&kvm_psci_host_cpu, target_cpu_id);
	target_init_params = per_cpu_ptr(&kvm_init_params, target_cpu_id);

	do {
		nvhe_spin_lock(&target_cpu->lock);

		if (target_cpu->power_state != KVM_HOST_CPU_POWER_OFF) {
			if (kvm_host_psci_version == PSCI_VERSION(0, 1))
				ret = PSCI_RET_INVALID_PARAMS;
			else if (target_cpu->power_state == KVM_HOST_CPU_POWER_ON)
				ret = PSCI_RET_ALREADY_ON;
			else
				ret = PSCI_RET_ON_PENDING;
			nvhe_spin_unlock(&target_cpu->lock);
			return ret;
		}

		target_cpu->reset_state = (struct vcpu_reset_state){
			.pc = pc,
			.r0 = r0,
			.reset = true,
		};

		ret = psci_call(kvm_host_psci_function_id[PSCI_FN_CPU_ON],
				mpidr,
				cpu_entry_pa(),
				__hyp_pa(target_init_params));

		if (ret == PSCI_RET_SUCCESS)
			target_cpu->power_state = KVM_HOST_CPU_POWER_PENDING_ON;

		nvhe_spin_unlock(&target_cpu->lock);

		/*
		 * If recorded CPU state is OFF but EL3 reports that it's ON,
		 * we must have hit a race with CPU_OFF on the target core.
		 * Loop to try again.
		 */
	} while (ret == PSCI_RET_ALREADY_ON);

	return ret;
}

static int psci_affinity_info(struct kvm_cpu_context *host_ctxt)
{
	u64 mpidr = host_ctxt->regs.regs[1] & MPIDR_HWID_BITMASK;
	unsigned long affinity_level = host_ctxt->regs.regs[2];
	unsigned int target_cpu_id;
	struct kvm_host_psci_cpu *target_cpu;

	/* The PSCI host driver only ever queries about level zero. */
	if (affinity_level != 0)
		return PSCI_RET_INVALID_PARAMS;

	target_cpu_id = find_cpu_id(mpidr);

	if (target_cpu_id == INVALID_CPU_ID)
		return PSCI_RET_INVALID_PARAMS;

	target_cpu = per_cpu_ptr(&kvm_psci_host_cpu, target_cpu_id);

	switch (target_cpu->power_state) {
	case KVM_HOST_CPU_POWER_OFF:
		return PSCI_0_2_AFFINITY_LEVEL_OFF;
	case KVM_HOST_CPU_POWER_PENDING_ON:
		return PSCI_0_2_AFFINITY_LEVEL_ON_PENDING;
	case KVM_HOST_CPU_POWER_ON:
		return PSCI_0_2_AFFINITY_LEVEL_ON;
	default:
		hyp_panic();
	}
}

static int __noreturn psci_system_off(void)
{
	psci_call(PSCI_0_2_FN_SYSTEM_OFF, 0, 0, 0);
	hyp_panic(); /* unreachable */
}

static int __noreturn psci_system_reset(void)
{
	psci_call(PSCI_0_2_FN_SYSTEM_RESET, 0, 0, 0);
	hyp_panic(); /* unreachable */
}

static int psci_system_reset2(struct kvm_cpu_context *host_ctxt)
{
	u32 reset_type = (u32)host_ctxt->regs.regs[1];
	u64 cookie = host_ctxt->regs.regs[2];

	/* Returns either NOT_SUPPORTED or INVALID_PARAMETERS. */
	return psci_call(PSCI_1_1_FN64_SYSTEM_RESET2, reset_type, cookie, 0);
}

static int psci_set_suspend_mode(struct kvm_cpu_context *host_ctxt)
{
	bool osi_mode = (bool)host_ctxt->regs.regs[1];

	return psci_call(PSCI_1_0_FN_SET_SUSPEND_MODE, osi_mode, 0, 0);
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
	// TODO: Need to narrow here?
	if (func_id == kvm_host_psci_function_id[PSCI_FN_CPU_SUSPEND])
		return psci_cpu_suspend(host_ctxt);
	else if (func_id == kvm_host_psci_function_id[PSCI_FN_CPU_OFF])
		return psci_cpu_off(host_ctxt);
	else if (func_id == kvm_host_psci_function_id[PSCI_FN_CPU_ON])
		return psci_cpu_on(host_ctxt);
	else
		return PSCI_RET_NOT_SUPPORTED;
}

static unsigned long psci_0_2_handler(struct kvm_cpu_context *host_ctxt)
{
	u64 func_id = get_psci_func_id(host_ctxt);

	if (is_psci_0_2_fn32_call(func_id))
		psci_narrow_to_32bit(host_ctxt);

	switch (func_id) {
	case PSCI_0_2_FN_PSCI_VERSION:
		return psci_version();
	case PSCI_0_2_FN64_CPU_SUSPEND:
		return psci_cpu_suspend(host_ctxt);
	case PSCI_0_2_FN_CPU_OFF:
		return psci_cpu_off(host_ctxt);
	case PSCI_0_2_FN64_CPU_ON:
		return psci_cpu_on(host_ctxt);
	case PSCI_0_2_FN64_AFFINITY_INFO:
		return psci_affinity_info(host_ctxt);
	case PSCI_0_2_FN_SYSTEM_OFF:
		psci_system_off();
		unreachable();
	case PSCI_0_2_FN_SYSTEM_RESET:
		psci_system_reset();
		unreachable();
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
	case PSCI_1_0_FN_PSCI_FEATURES:
		return psci_features(host_ctxt);
	case PSCI_1_0_FN_SET_SUSPEND_MODE:
		return psci_set_suspend_mode(host_ctxt);
	case PSCI_1_1_FN64_SYSTEM_RESET2:
		return psci_system_reset2(host_ctxt);
	default:
		return PSCI_RET_NOT_SUPPORTED;
	}
}

void __noreturn __host_enter(struct kvm_cpu_context *host_ctxt);

void kvm_host_psci_cpu_init(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_host_psci_cpu *host_cpu = this_cpu_ptr(&kvm_psci_host_cpu);

	nvhe_spin_lock(&host_cpu->lock);
	if (host_cpu->reset_state.reset) {
		/* XXX - need a full wipe here? */
		host_ctxt->regs.regs[0] = host_cpu->reset_state.r0;
		host_ctxt->regs.pc = host_cpu->reset_state.pc;
		host_cpu->reset_state.reset = false;
		write_sysreg_el2(host_ctxt->regs.pc, SYS_ELR);
	}
	host_cpu->power_state = KVM_HOST_CPU_POWER_ON;
	nvhe_spin_unlock(&host_cpu->lock);

	__host_enter(host_ctxt);
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
