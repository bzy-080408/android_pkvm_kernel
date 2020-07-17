// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <linux/compiler.h>

#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_host.h>
#include <asm/kvm_psci.h>

#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>

#include <uapi/linux/psci.h>

#include <nvhe/spinlock.h>

#include "../debug-pl011.h"

static DEFINE_PER_CPU(nvhe_spinlock_t, kvm_psci_cpu_lock)= NVHE_SPIN_LOCK_INIT;
DECLARE_PER_CPU(struct kvm_hyp_init_params, kvm_cpu_params);

#define kvm_next_host_vcpu(idx)					\
	({							\
		do {						\
			idx++;					\
		} while (idx < nr_cpu_ids &&			\
			 cpu_logical_map(idx) == INVALID_HWID);	\
		idx;						\
	})

#define kvm_for_each_host_vcpu(idx)				\
	for (idx = 0; idx < nr_cpu_ids; kvm_next_host_vcpu(idx))

static int find_cpu_id(u64 mpidr)
{
	int cpu;

	kvm_for_each_host_vcpu(cpu) {
		if (cpu_logical_map(cpu) == mpidr)
			return cpu;
	}
	return -1;
}

static unsigned long kvm_cpu_start_pa(void)
{
	extern char __kvm_cpu_start[];
	unsigned long sym_kern_va;

	asm volatile("ldr %0, =%1" : "=r" (sym_kern_va) : "S" (__kvm_cpu_start));
	return sym_kern_va - kimage_voffset;
}

void kvm_host_psci_init_cpu(struct kvm_vcpu *vcpu)
{
	nvhe_spinlock_t *cpu_lock = this_cpu_ptr(&kvm_psci_cpu_lock);

	nvhe_spin_lock(cpu_lock);
	vcpu->arch.power_off = false;
	if (vcpu->arch.reset_state.reset) {
		vcpu->arch.reset_state.reset = false;

		*vcpu_pc(vcpu) = vcpu->arch.reset_state.pc;
		vcpu_set_reg(vcpu, 0, vcpu->arch.reset_state.r0);

		/* XXX - add more from KVM vcpu reset (search for arch.reset_state) */

		write_sysreg_el2(vcpu_gp_regs(vcpu)->pstate, SYS_SPSR);
		write_sysreg_el2(*vcpu_pc(vcpu), SYS_ELR);
	}
	nvhe_spin_unlock(cpu_lock);
}

static int kvm_host_psci_cpu_on(unsigned long mpidr, unsigned long pc,
				unsigned long r0)
{
	int ret;
	struct arm_smccc_res res;
	int cpu_id = find_cpu_id(mpidr);
	nvhe_spinlock_t *cpu_lock;
	struct kvm_vcpu *vcpu;

	if (cpu_id < 0)
		return PSCI_RET_INVALID_PARAMS;

	cpu_lock = per_cpu_ptr(&kvm_psci_cpu_lock, cpu_id);
	vcpu = per_cpu_ptr(&kvm_host_vcpu, cpu_id);

	nvhe_spin_lock(cpu_lock);

	/* XXX - check that this CPU had KVM initialized on it */
	// 	ret = PSCI_RET_INTERNAL_FAILURE;
	// 	goto out;
	// }

	if (!vcpu->arch.power_off) {
		ret = PSCI_RET_ALREADY_ON;
		goto out;
	}

	vcpu->arch.reset_state.reset = true;
	vcpu->arch.reset_state.pc = pc;
	vcpu->arch.reset_state.r0 = r0;

	/*
	 * There is a race with CPU_OFF. Repeat if the CPU is in the process
	 * of being turned off.
	 */
	do {
		arm_smccc_1_1_smc(PSCI_0_2_FN64_CPU_ON, mpidr,
				  kvm_cpu_start_pa(),
				  per_cpu_ptr(&kvm_cpu_params, cpu_id)->this_phys_addr,
				  &res);
		ret = res.a0;
		hyp_putx32(ret);
	} while (ret == PSCI_RET_ALREADY_ON);

	vcpu->arch.power_off = false;

out:
	nvhe_spin_unlock(cpu_lock);
	return ret;
}

int kvm_host_psci_cpu_off(void)
{
	nvhe_spinlock_t *cpu_lock = this_cpu_ptr(&kvm_psci_cpu_lock);
	struct kvm_vcpu *vcpu = this_cpu_ptr(&kvm_host_vcpu);

	nvhe_spin_lock(cpu_lock);
	vcpu->arch.power_off = true;
	nvhe_spin_unlock(cpu_lock);

	arm_smccc_1_1_smc(PSCI_0_2_FN_CPU_OFF, NULL);

	/* XXX - do we want to panic? */
	return PSCI_RET_DENIED;
}

int kvm_host_psci_affinity_info(unsigned long target_affinity,
				unsigned long lowest_affinity_level)
{
	unsigned int cpu_id;
	unsigned long target_affinity_mask;
	bool found_matching_cpu;
	struct kvm_vcpu *vcpu;

	target_affinity_mask = kvm_psci_affinity_mask(lowest_affinity_level);
	if (!target_affinity_mask)
		return PSCI_RET_INVALID_PARAMS;

	found_matching_cpu = false;
	kvm_for_each_host_vcpu(cpu_id) {
		if ((cpu_logical_map(cpu_id) & target_affinity_mask) == target_affinity) {
			found_matching_cpu = true;
			vcpu = per_cpu_ptr(&kvm_host_vcpu, cpu_id);
			if (!vcpu->arch.power_off)
				return PSCI_0_2_AFFINITY_LEVEL_ON;
		}
	}

	if (!found_matching_cpu)
		return PSCI_RET_INVALID_PARAMS;

	return PSCI_0_2_AFFINITY_LEVEL_OFF;
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
	case PSCI_0_2_FN_AFFINITY_INFO:
		kvm_psci_narrow_to_32bit(host_vcpu);
		fallthrough;
	case PSCI_0_2_FN64_AFFINITY_INFO:
		return kvm_host_psci_affinity_info(smccc_get_arg1(host_vcpu),
					           smccc_get_arg2(host_vcpu));
	case PSCI_0_2_FN_CPU_OFF:
		return kvm_host_psci_cpu_off();
	case PSCI_0_2_FN_CPU_ON:
		kvm_psci_narrow_to_32bit(host_vcpu);
		fallthrough;
	case PSCI_0_2_FN64_CPU_ON:
		return kvm_host_psci_cpu_on(smccc_get_arg1(host_vcpu),
					    smccc_get_arg2(host_vcpu),
					    smccc_get_arg3(host_vcpu));
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
