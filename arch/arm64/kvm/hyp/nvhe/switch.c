// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <hyp/adjust_pc.h>
#include <hyp/switch.h>
#include <hyp/sysreg-sr.h>

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <uapi/linux/psci.h>

#include <kvm/arm_psci.h>

#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/kprobes.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/thread_info.h>

#include <nvhe/mem_protect.h>
#include <nvhe/pkvm.h>

/* Non-VHE specific context */
DEFINE_PER_CPU(struct kvm_host_data, kvm_host_data);
DEFINE_PER_CPU(struct kvm_cpu_context, kvm_hyp_ctxt);
DEFINE_PER_CPU(unsigned long, kvm_hyp_vector);

/* Activate traps for protected guests */
static void __activate_traps_pvm(struct kvm_vcpu_arch_core *core_state)
{
	u64 val;

	___activate_traps(core_state);
	__activate_traps_common(core_state);

	val = CPTR_EL2_DEFAULT;
	val |= CPTR_EL2_TTA | CPTR_EL2_TAM;

	write_sysreg(val, cptr_el2);
	write_sysreg(__this_cpu_read(kvm_hyp_vector), vbar_el2);

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		struct kvm_cpu_context *ctxt = &core_state->ctxt;

		isb();
		/*
		 * At this stage, and thanks to the above isb(), S2 is
		 * configured and enabled. We can now restore the guest's S1
		 * configuration: SCTLR, and only then TCR.
		 */
		write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR_EL1),	SYS_SCTLR);
		isb();
		write_sysreg_el1(ctxt_sys_reg(ctxt, TCR_EL1),	SYS_TCR);
	}
}

/* Activate traps for non-protected guests in nVHE */
static void __activate_traps_nvhe(struct kvm_vcpu *vcpu)
{
	__activate_traps_pvm(&vcpu->arch.core_state);

	if (!update_fp_enabled(vcpu)) {
		u64 val = read_sysreg(cptr_el2);
		val |= CPTR_EL2_TFP | CPTR_EL2_TZ;
		__activate_traps_fpsimd32(vcpu);
		write_sysreg(val, cptr_el2);
	}
}

static void __deactivate_traps(struct kvm_vcpu_arch_core *core_state)
{
	extern char __kvm_hyp_host_vector[];
	u64 mdcr_el2, cptr;

	___deactivate_traps(core_state);

	mdcr_el2 = read_sysreg(mdcr_el2);

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		u64 val;

		/*
		 * Set the TCR and SCTLR registers in the exact opposite
		 * sequence as __activate_traps (first prevent walks,
		 * then force the MMU on). A generous sprinkling of isb()
		 * ensure that things happen in this exact order.
		 */
		val = read_sysreg_el1(SYS_TCR);
		write_sysreg_el1(val | TCR_EPD1_MASK | TCR_EPD0_MASK, SYS_TCR);
		isb();
		val = read_sysreg_el1(SYS_SCTLR);
		write_sysreg_el1(val | SCTLR_ELx_M, SYS_SCTLR);
		isb();
	}

	__deactivate_traps_common();

	mdcr_el2 &= MDCR_EL2_HPMN_MASK;
	mdcr_el2 |= MDCR_EL2_E2PB_MASK << MDCR_EL2_E2PB_SHIFT;

	write_sysreg(mdcr_el2, mdcr_el2);
	write_sysreg(this_cpu_ptr(&kvm_init_params)->hcr_el2, hcr_el2);

	cptr = CPTR_EL2_DEFAULT;
	if (vcpu_has_sve(core_state) && (core_state->flags & KVM_ARM64_FP_ENABLED))
		cptr |= CPTR_EL2_TZ;

	write_sysreg(cptr, cptr_el2);
	write_sysreg(__kvm_hyp_host_vector, vbar_el2);
}

/* Save VGICv3 state on non-VHE systems */
static void __hyp_vgic_save_state(struct kvm_vcpu *vcpu)
{
	if (static_branch_unlikely(&kvm_vgic_global_state.gicv3_cpuif)) {
		__vgic_v3_save_state(&vcpu->arch.vgic_cpu.vgic_v3);
		__vgic_v3_deactivate_traps(&vcpu->arch.vgic_cpu.vgic_v3);
	}
}

/* Restore VGICv3 state on nVHE systems */
static void __hyp_vgic_restore_state(struct kvm_vcpu *vcpu)
{
	if (static_branch_unlikely(&kvm_vgic_global_state.gicv3_cpuif)) {
		__vgic_v3_activate_traps(&vcpu->arch.vgic_cpu.vgic_v3);
		__vgic_v3_restore_state(&vcpu->arch.vgic_cpu.vgic_v3);
	}
}

/**
 * Disable host events, enable guest events
 */
static bool __pmu_switch_to_guest(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_host_data *host;
	struct kvm_pmu_events *pmu;

	host = container_of(host_ctxt, struct kvm_host_data, host_ctxt);
	pmu = &host->pmu_events;

	if (pmu->events_host)
		write_sysreg(pmu->events_host, pmcntenclr_el0);

	if (pmu->events_guest)
		write_sysreg(pmu->events_guest, pmcntenset_el0);

	return (pmu->events_host || pmu->events_guest);
}

/**
 * Disable guest events, enable host events
 */
static void __pmu_switch_to_host(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_host_data *host;
	struct kvm_pmu_events *pmu;

	host = container_of(host_ctxt, struct kvm_host_data, host_ctxt);
	pmu = &host->pmu_events;

	if (pmu->events_guest)
		write_sysreg(pmu->events_guest, pmcntenclr_el0);

	if (pmu->events_host)
		write_sysreg(pmu->events_host, pmcntenset_el0);
}

void handle_entry_wfx(const struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
	const struct kvm_vcpu_arch_core *host_core = &vcpu->arch.core_state;

	/* TODO: Don't copy verbatim. Sanitize. */
	core_state->flags = host_core->flags;
}

void handle_entry_hvc(const struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
	const struct kvm_vcpu_arch_core *host_core = &vcpu->arch.core_state;

	vcpu_set_reg(core_state, 0, vcpu_get_reg(host_core, 0));
	vcpu_set_reg(core_state, 1, vcpu_get_reg(host_core, 1));
	vcpu_set_reg(core_state, 2, vcpu_get_reg(host_core, 2));
	vcpu_set_reg(core_state, 3, vcpu_get_reg(host_core, 3));

	/*
	 * TODO: Handle potential changes from PSCI calls.
	 */
}

void handle_entry_sys64(const struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
	const struct kvm_vcpu_arch_core *host_core = &vcpu->arch.core_state;
	u32 esr_el2 = core_state->fault.esr_el2;

	/* TODO: Don't copy verbatim. Sanitize. */
	core_state->flags = host_core->flags;

	if (core_state->flags & KVM_ARM64_PENDING_EXCEPTION) {
		/* All exceptions caused by this should be undef exceptions. */
		u32 esr_el1 = (ESR_ELx_EC_UNKNOWN << ESR_ELx_EC_SHIFT);

		__vcpu_sys_reg(core_state, ESR_EL1) = esr_el1;
	} else if (esr_el2 & ESR_ELx_SYS64_ISS_DIR_READ) {
		u64 rt_val = vcpu_get_reg(host_core, 0);
		int rt = kvm_vcpu_sys_get_rt(core_state);

		vcpu_set_reg(core_state, rt, rt_val);
	}
}

void handle_entry_abt(const struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
	// TODO: deal with kvm_set_sei_esr(), which might be called in RAS. Would it?

	const struct kvm_vcpu_arch_core *host_core = &vcpu->arch.core_state;

	/* TODO: Don't copy verbatim. Sanitize. */
	core_state->flags = host_core->flags;

	if (core_state->flags & KVM_ARM64_PENDING_EXCEPTION) {
		/* If the host wants to inject an exception, get syndrom and fault address. */
		u32 esr_el1;
		u32 far_el1 = kvm_vcpu_get_hfar(core_state);

		if (kvm_vcpu_trap_is_iabt(core_state))
			esr_el1 = ESR_ELx_EC_IABT_CUR << ESR_ELx_EC_SHIFT;
		else
			esr_el1 = ESR_ELx_EC_DABT_LOW << ESR_ELx_EC_SHIFT;

		esr_el1 |= ESR_ELx_FSC_EXTABT;

		__vcpu_sys_reg(core_state, ESR_EL1) = esr_el1;
		__vcpu_sys_reg(core_state, FAR_EL1) = far_el1;
	} else if (!kvm_vcpu_dabt_iswrite(core_state)) {
		/* r0 is used for communicating between guest and host. */
		u64 rd_val = vcpu_get_reg(host_core, 0);
		int rd = kvm_vcpu_dabt_get_rd(core_state);

		vcpu_set_reg(core_state, rd, rd_val);
	}
}

static int handle_exit_wfx(struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
	if (is_nvhe_hyp_code()) {
		struct kvm_vcpu_arch_core *host_core = &vcpu->arch.core_state;
		u32 esr_el2 = core_state->fault.esr_el2;

		/* TODO: Don't copy verbatim. Sanitize. */
		host_core->flags = core_state->flags;
		host_core->fault.esr_el2 = esr_el2;

		core_state->pkvm.host_request_pending = true;
	}

	/* All is set up for the host to handle this. */
	return 0;
}

static int handle_exit_sys64(struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
	if (is_nvhe_hyp_code()) {
		struct kvm_vcpu_arch_core *host_core = &vcpu->arch.core_state;
		u32 esr_el2 = core_state->fault.esr_el2;

		/* TODO: Don't copy verbatim. Sanitize. */
		host_core->flags = core_state->flags;

		/* Host should not know the value of Rt. Set it to r0. */
		host_core->fault.esr_el2 = esr_el2 & ~ESR_ELx_SYS64_ISS_RT_MASK;

		/* For writes, pass the value to the host in its r0. */
		if (esr_el2 & ESR_ELx_SYS64_ISS_DIR_WRITE) {
			int rt = kvm_vcpu_sys_get_rt(core_state);
			u64 rt_val = vcpu_get_reg(core_state, rt);

			vcpu_set_reg(host_core, 0, rt_val);
		}

		core_state->pkvm.host_request_pending = true;
	}

	/* All is set up for the host to handle this. */
	return 0;
}

static int handle_exit_hvc(struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
	if (is_nvhe_hyp_code()) {
		struct kvm_vcpu_arch_core *host_core = &vcpu->arch.core_state;

		host_core->fault.esr_el2 = core_state->fault.esr_el2;

		/* SMCC in linux handles only four registers. */
		vcpu_set_reg(host_core, 0, vcpu_get_reg(core_state, 0));
		vcpu_set_reg(host_core, 1, vcpu_get_reg(core_state, 1));
		vcpu_set_reg(host_core, 2, vcpu_get_reg(core_state, 2));
		vcpu_set_reg(host_core, 3, vcpu_get_reg(core_state, 3));

		core_state->pkvm.host_request_pending = true;
	}

	/* All is set up for the host to handle this. */
	return 0;
}

static int handle_exit_abt(struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
	if (is_nvhe_hyp_code()) {
		struct kvm_vcpu_arch_core *host_core = &vcpu->arch.core_state;
		u32 esr_el2 = core_state->fault.esr_el2;

		/* TODO: Don't copy verbatim. Sanitize. */
		host_core->flags = core_state->flags;

		/*
		 * Host should not know what Rt is. All data exchange is done
		 * though r0 in hyp_run using r0 in the host's vcpu as a proxy.
		 */
		if (esr_is_data_abort(esr_el2))
			esr_el2 &= ~ESR_ELx_SRT_MASK;

		/* TODO: Don't copy verbatim. Sanitize. */
		host_core->fault.esr_el2 = esr_el2;
		host_core->fault.far_el2 = core_state->fault.far_el2;
		host_core->fault.hpfar_el2 = core_state->fault.hpfar_el2;
		host_core->fault.disr_el1 = core_state->fault.disr_el1;

		if (kvm_vcpu_dabt_iswrite(core_state)) {
			int rt = kvm_vcpu_dabt_get_rd(core_state);
			u64 rt_val = vcpu_get_reg(core_state, rt);

			vcpu_set_reg(host_core, 0, rt_val);
		}

		/* TODO: not quite sure why this is needed. Investigate. */
		if (kvm_vcpu_trap_is_iabt(core_state))
			vcpu_set_reg(host_core, 0, vcpu_get_reg(core_state, 0));

		core_state->pkvm.host_request_pending = true;
	}

	/* All is set up for the host to handle this. */
	return 0;
}

typedef void (*entry_handle_fn)(const struct kvm_vcpu *, struct kvm_vcpu_arch_core *);

static entry_handle_fn hyp_entry_handlers[] = {
	[0 ... ESR_ELx_EC_MAX]		= NULL,
	[ESR_ELx_EC_WFx]		= handle_entry_wfx,
	[ESR_ELx_EC_CP15_32]		= NULL,
	[ESR_ELx_EC_CP15_64]		= NULL,
	[ESR_ELx_EC_CP14_MR]		= NULL,
	[ESR_ELx_EC_CP14_LS]		= NULL,
	[ESR_ELx_EC_CP14_64]		= NULL,
	[ESR_ELx_EC_HVC32]		= NULL,
	[ESR_ELx_EC_SMC32]		= NULL,
	[ESR_ELx_EC_HVC64]		= handle_entry_hvc,
	[ESR_ELx_EC_SMC64]		= NULL,
	[ESR_ELx_EC_SYS64]		= handle_entry_sys64,
	[ESR_ELx_EC_SVE]		= NULL,
	[ESR_ELx_EC_IABT_LOW]		= handle_entry_abt,
	[ESR_ELx_EC_DABT_LOW]		= handle_entry_abt,
	[ESR_ELx_EC_SOFTSTP_LOW]	= NULL,
	[ESR_ELx_EC_WATCHPT_LOW]	= NULL,
	[ESR_ELx_EC_BREAKPT_LOW]	= NULL,
	[ESR_ELx_EC_BKPT32]		= NULL,
	[ESR_ELx_EC_BRK64]		= NULL,
	[ESR_ELx_EC_FP_ASIMD]		= NULL,
	[ESR_ELx_EC_PAC]		= NULL,
};

static exit_handle_fn hyp_exit_handlers[] = {
	[0 ... ESR_ELx_EC_MAX]		= NULL,
	[ESR_ELx_EC_WFx]		= handle_exit_wfx,
	[ESR_ELx_EC_CP15_32]		= NULL,
	[ESR_ELx_EC_CP15_64]		= NULL,
	[ESR_ELx_EC_CP14_MR]		= NULL,
	[ESR_ELx_EC_CP14_LS]		= NULL,
	[ESR_ELx_EC_CP14_64]		= NULL,
	[ESR_ELx_EC_HVC32]		= NULL,
	[ESR_ELx_EC_SMC32]		= NULL,
	[ESR_ELx_EC_HVC64]		= handle_exit_hvc,
	[ESR_ELx_EC_SMC64]		= NULL,
	[ESR_ELx_EC_SYS64]		= handle_exit_sys64,
	[ESR_ELx_EC_SVE]		= NULL,
	[ESR_ELx_EC_IABT_LOW]		= handle_exit_abt,
	[ESR_ELx_EC_DABT_LOW]		= handle_exit_abt,
	[ESR_ELx_EC_SOFTSTP_LOW]	= NULL,
	[ESR_ELx_EC_WATCHPT_LOW]	= NULL,
	[ESR_ELx_EC_BREAKPT_LOW]	= NULL,
	[ESR_ELx_EC_BKPT32]		= NULL,
	[ESR_ELx_EC_BRK64]		= NULL,
	[ESR_ELx_EC_FP_ASIMD]		= NULL,
	[ESR_ELx_EC_PAC]		= NULL,
};

exit_handle_fn kvm_get_nvhe_exit_handler(struct kvm_vcpu_arch_core *core_state)
{
	u32 esr = kvm_vcpu_get_esr(core_state);
	u8 esr_ec = ESR_ELx_EC(esr);


	return hyp_exit_handlers[esr_ec];
}

static void __process_hyp_vcpu_run_entry_state(struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
	entry_handle_fn entry_handler;
	u8 esr_ec;

	if (!core_state->pkvm.host_request_pending)
		return;

	esr_ec = ESR_ELx_EC(kvm_vcpu_get_esr(core_state));

	/* TODO: For debugging. Remove. */
	if (esr_ec >= ESR_ELx_EC_MAX)
		HYP_PANIC;

	entry_handler = hyp_entry_handlers[esr_ec];

	/* TODO: For debugging. Remove. */
	if (!entry_handler)
		HYP_PANIC;

	entry_handler(vcpu, core_state);

	core_state->pkvm.host_request_pending = false;
}

static void __process_hyp_vcpu_run_exit_state(struct kvm_vcpu *vcpu, struct kvm_vcpu_arch_core *core_state)
{
}

/* Switch to the non-protected guest */
static int __kvm_vcpu_run_nvhe(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_arch_core *core_state = &vcpu->arch.core_state;
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	bool pmu_switch_needed;
	u64 exit_code;

	/*
	 * Having IRQs masked via PMR when entering the guest means the GIC
	 * will not signal the CPU of interrupts of lower priority, and the
	 * only way to get out will be via guest exceptions.
	 * Naturally, we want to avoid this.
	 */
	if (system_uses_irq_prio_masking()) {
		gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET);
		pmr_sync();
	}

	host_ctxt = &this_cpu_ptr(&kvm_host_data)->host_ctxt;
	host_ctxt->__hyp_running_vcpu = core_state;
	guest_ctxt = &core_state->ctxt;

	pmu_switch_needed = __pmu_switch_to_guest(host_ctxt);

	__sysreg_save_state_nvhe(host_ctxt);
	/*
	 * We must flush and disable the SPE buffer for nVHE, as
	 * the translation regime(EL1&0) is going to be loaded with
	 * that of the guest. And we must do this before we change the
	 * translation regime to EL2 (via MDCR_EL2_E2PB == 0) and
	 * before we load guest Stage1.
	 */
	__debug_save_host_buffers_nvhe(vcpu);

	__adjust_pc(core_state);

	/*
	 * We must restore the 32-bit state before the sysregs, thanks
	 * to erratum #852523 (Cortex-A57) or #853709 (Cortex-A72).
	 *
	 * Also, and in order to be able to deal with erratum #1319537 (A57)
	 * and #1319367 (A72), we must ensure that all VM-related sysreg are
	 * restored before we enable S2 translation.
	 */
	__sysreg32_restore_state(core_state);
	__sysreg_restore_state_nvhe(guest_ctxt);

	__load_guest_stage2(kern_hyp_va(vcpu->arch.hw_mmu));
	__activate_traps_nvhe(vcpu);

	__hyp_vgic_restore_state(vcpu);
	__timer_enable_traps();

	__debug_switch_to_guest(vcpu);

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(core_state);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code));

	__sysreg_save_state_nvhe(guest_ctxt);
	__sysreg32_save_state(core_state);
	__timer_disable_traps();
	__hyp_vgic_save_state(vcpu);

	__deactivate_traps(core_state);
	__load_host_stage2();

	__sysreg_restore_state_nvhe(host_ctxt);

	if (core_state->flags & KVM_ARM64_FP_ENABLED)
		__fpsimd_save_fpexc32(vcpu);

	__debug_switch_to_host(vcpu);
	/*
	 * This must come after restoring the host sysregs, since a non-VHE
	 * system may enable SPE here and make use of the TTBRs.
	 */
	__debug_restore_host_buffers_nvhe(vcpu);

	if (pmu_switch_needed)
		__pmu_switch_to_host(host_ctxt);

	/* Returning to host will clear PSR.I, remask PMR if needed */
	if (system_uses_irq_prio_masking())
		gic_write_pmr(GIC_PRIO_IRQOFF);

	host_ctxt->__hyp_running_vcpu = NULL;

	return exit_code;
}

/* Switch to the protected guest */
static int __kvm_vcpu_run_pvm(struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_arch_core *core_state = hyp_get_shadow_core(vcpu);
	/* TODO: This will be the shadow KVM. */
	struct kvm *kvm = kern_hyp_va(vcpu->kvm);
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	u64 exit_code;

	// TODO: Sanity checking for testing only. To be removed.
	{
		const struct kvm *shadow_kvm;

		HYP_ASSERT(core_state);
		HYP_ASSERT(core_state != &vcpu->arch.core_state);

		shadow_kvm = core_state->pkvm.kvm;
		HYP_ASSERT(shadow_kvm);
		HYP_ASSERT(shadow_kvm != vcpu->kvm);
		HYP_ASSERT(shadow_kvm != kvm);
		HYP_ASSERT(shadow_kvm->created_vcpus == kvm->created_vcpus);
		HYP_ASSERT(shadow_kvm->arch.max_vcpus == kvm->arch.max_vcpus);
		HYP_ASSERT(shadow_kvm->arch.pfr0_csv2 == kvm->arch.pfr0_csv2);
		HYP_ASSERT(shadow_kvm->arch.pfr0_csv3 == kvm->arch.pfr0_csv3);
		HYP_ASSERT(shadow_kvm->arch.pkvm.enabled);
		HYP_ASSERT(shadow_kvm->arch.pkvm.shadow_handle > 0);
		HYP_ASSERT(shadow_kvm->arch.pkvm.shadow_handle ==
			   kvm->arch.pkvm.shadow_handle);
		HYP_ASSERT(shadow_kvm->arch.pkvm.shadow_handle ==
			   core_state->pkvm.shadow_handle);
		HYP_ASSERT(shadow_kvm->arch.pkvm.firmware_slot ==
			   kern_hyp_va(kvm->arch.pkvm.firmware_slot));
	}

	/*
	 * Having IRQs masked via PMR when entering the guest means the GIC
	 * will not signal the CPU of interrupts of lower priority, and the
	 * only way to get out will be via guest exceptions.
	 * Naturally, we want to avoid this.
	 */
	if (system_uses_irq_prio_masking()) {
		gic_write_pmr(GIC_PRIO_IRQON | GIC_PRIO_PSR_I_SET);
		pmr_sync();
	}

	host_ctxt = &this_cpu_ptr(&kvm_host_data)->host_ctxt;
	host_ctxt->__hyp_running_vcpu = core_state;
	guest_ctxt = &core_state->ctxt;

	__sysreg_save_state_nvhe(host_ctxt);

	__process_hyp_vcpu_run_entry_state(vcpu, core_state);
	__adjust_pc(core_state);

	__sysreg_restore_state_nvhe(guest_ctxt);

	/* TODO: This will be the shadow hw_mmu. */
	__load_guest_stage2(kern_hyp_va(vcpu->arch.hw_mmu));
	__activate_traps_pvm(core_state);

	__hyp_vgic_restore_state(vcpu);
	__timer_enable_traps();

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(core_state);

		/* And we're baaack! */
	} while (fixup_pvm_guest_exit(kvm, vcpu, core_state, &exit_code));

	__sysreg_save_state_nvhe(guest_ctxt);
	__timer_disable_traps();
	__hyp_vgic_save_state(vcpu);

	__deactivate_traps(core_state);
	__load_host_stage2();

	__process_hyp_vcpu_run_exit_state(vcpu, core_state);
	__sysreg_restore_state_nvhe(host_ctxt);

	/* Returning to host will clear PSR.I, remask PMR if needed */
	if (system_uses_irq_prio_masking())
		gic_write_pmr(GIC_PRIO_IRQOFF);

	host_ctxt->__hyp_running_vcpu = NULL;

	return exit_code;
}


/* Switch to the guest for non-VHE and protected KVM systems */
int __kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	vcpu = kern_hyp_va(vcpu);

	if (likely(!kvm_vm_is_protected(kern_hyp_va(vcpu->kvm))))
		return __kvm_vcpu_run_nvhe(vcpu);
	else
		return __kvm_vcpu_run_pvm(vcpu);
}

void __noreturn hyp_panic(void)
{
	u64 spsr = read_sysreg_el2(SYS_SPSR);
	u64 elr = read_sysreg_el2(SYS_ELR);
	u64 par = read_sysreg_par();
	struct kvm_cpu_context *host_ctxt;
	struct kvm_vcpu_arch_core *core_state;

	host_ctxt = &this_cpu_ptr(&kvm_host_data)->host_ctxt;
	core_state = host_ctxt->__hyp_running_vcpu;

	if (core_state) {
		__timer_disable_traps();
		__deactivate_traps(core_state);
		__load_host_stage2();
		__sysreg_restore_state_nvhe(host_ctxt);
	}

	__hyp_do_panic(host_ctxt, spsr, elr, par);
	unreachable();
}

asmlinkage void kvm_unexpected_el2_exception(void)
{
	return __kvm_unexpected_el2_exception();
}
