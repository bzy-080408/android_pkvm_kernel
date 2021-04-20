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
	struct kvm_vcpu_arch_core *core_state = &vcpu->arch.core_state;
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
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

	__sysreg_save_state_nvhe(host_ctxt);

	__adjust_pc(core_state);

	__sysreg_restore_state_nvhe(guest_ctxt);

	__load_guest_stage2(kern_hyp_va(vcpu->arch.hw_mmu));
	__activate_traps_pvm(core_state);

	__hyp_vgic_restore_state(vcpu);
	__timer_enable_traps();

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(core_state);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code));

	__sysreg_save_state_nvhe(guest_ctxt);
	__timer_disable_traps();
	__hyp_vgic_save_state(vcpu);

	__deactivate_traps(core_state);
	__load_host_stage2();

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
