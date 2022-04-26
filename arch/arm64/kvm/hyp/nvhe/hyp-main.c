// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <hyp/adjust_pc.h>

#include <asm/pgtable-types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include <nvhe/trap_handler.h>

#include <linux/irqchip/arm-gic-v3.h>

/*
 * Host FPSIMD state. Written to when the guest accesses its own FPSIMD state,
 * and read when the guest state is live and we need to switch back to the host.
 *
 * Only valid when (fp_state == FP_STATE_GUEST_OWNED) in the shadow structure.
 */
static DEFINE_PER_CPU(struct user_fpsimd_state, loaded_host_fpsimd_state);

DEFINE_PER_CPU(struct kvm_nvhe_init_params, kvm_init_params);

void __kvm_hyp_host_forward_smc(struct kvm_cpu_context *host_ctxt);

typedef void (*shadow_entry_exit_handler_fn)(struct kvm_vcpu *, struct kvm_vcpu *);

static void handle_vm_entry_generic(struct kvm_vcpu *host_vcpu, struct kvm_vcpu *shadow_vcpu)
{
	vcpu_copy_flag(shadow_vcpu, host_vcpu, PC_UPDATE_REQ);
}

static void handle_vm_exit_generic(struct kvm_vcpu *host_vcpu, struct kvm_vcpu *shadow_vcpu)
{
	WRITE_ONCE(host_vcpu->arch.fault.esr_el2,
		   shadow_vcpu->arch.fault.esr_el2);
}

static void handle_vm_exit_abt(struct kvm_vcpu *host_vcpu, struct kvm_vcpu *shadow_vcpu)
{
	WRITE_ONCE(host_vcpu->arch.fault.esr_el2,
		   shadow_vcpu->arch.fault.esr_el2);
	WRITE_ONCE(host_vcpu->arch.fault.far_el2,
		   shadow_vcpu->arch.fault.far_el2);
	WRITE_ONCE(host_vcpu->arch.fault.hpfar_el2,
		   shadow_vcpu->arch.fault.hpfar_el2);
	WRITE_ONCE(host_vcpu->arch.fault.disr_el1,
		   shadow_vcpu->arch.fault.disr_el1);
}

static const shadow_entry_exit_handler_fn entry_vm_shadow_handlers[] = {
	[0 ... ESR_ELx_EC_MAX]		= handle_vm_entry_generic,
};

static const shadow_entry_exit_handler_fn exit_vm_shadow_handlers[] = {
	[0 ... ESR_ELx_EC_MAX]		= handle_vm_exit_generic,
	[ESR_ELx_EC_IABT_LOW]		= handle_vm_exit_abt,
	[ESR_ELx_EC_DABT_LOW]		= handle_vm_exit_abt,
};

static void flush_vgic_state(struct kvm_vcpu *host_vcpu,
			     struct kvm_vcpu *shadow_vcpu)
{
	struct vgic_v3_cpu_if *host_cpu_if, *shadow_cpu_if;
	unsigned int used_lrs, max_lrs, i;

	host_cpu_if	= &host_vcpu->arch.vgic_cpu.vgic_v3;
	shadow_cpu_if	= &shadow_vcpu->arch.vgic_cpu.vgic_v3;

	max_lrs = (read_gicreg(ICH_VTR_EL2) & 0xf) + 1;
	used_lrs = READ_ONCE(host_cpu_if->used_lrs);
	used_lrs = min(used_lrs, max_lrs);

	shadow_cpu_if->vgic_hcr	= READ_ONCE(host_cpu_if->vgic_hcr);
	/* Should be a one-off */
	shadow_cpu_if->vgic_sre = (ICC_SRE_EL1_DIB |
				   ICC_SRE_EL1_DFB |
				   ICC_SRE_EL1_SRE);
	shadow_cpu_if->used_lrs	= used_lrs;

	for (i = 0; i < used_lrs; i++)
		shadow_cpu_if->vgic_lr[i] = READ_ONCE(host_cpu_if->vgic_lr[i]);
}

static void sync_vgic_state(struct kvm_vcpu *host_vcpu,
			    struct kvm_vcpu *shadow_vcpu)
{
	struct vgic_v3_cpu_if *host_cpu_if, *shadow_cpu_if;
	unsigned int i;

	host_cpu_if	= &host_vcpu->arch.vgic_cpu.vgic_v3;
	shadow_cpu_if	= &shadow_vcpu->arch.vgic_cpu.vgic_v3;

	WRITE_ONCE(host_cpu_if->vgic_hcr, shadow_cpu_if->vgic_hcr);

	for (i = 0; i < shadow_cpu_if->used_lrs; i++)
		WRITE_ONCE(host_cpu_if->vgic_lr[i], shadow_cpu_if->vgic_lr[i]);
}

static void flush_timer_state(struct kvm_shadow_vcpu_state *shadow_state)
{
	struct kvm_vcpu *shadow_vcpu = &shadow_state->shadow_vcpu;

	if (!shadow_state_is_protected(shadow_state))
		return;

	/*
	 * A shadow vcpu has no offset, and sees vtime == ptime. The
	 * ptimer is fully emulated by EL1 and cannot be trusted.
	 */
	write_sysreg(0, cntvoff_el2);
	isb();
	write_sysreg_el0(__vcpu_sys_reg(shadow_vcpu, CNTV_CVAL_EL0), SYS_CNTV_CVAL);
	write_sysreg_el0(__vcpu_sys_reg(shadow_vcpu, CNTV_CTL_EL0), SYS_CNTV_CTL);
}

static void sync_timer_state(struct kvm_shadow_vcpu_state *shadow_state)
{
	struct kvm_vcpu *shadow_vcpu = &shadow_state->shadow_vcpu;

	if (!shadow_state_is_protected(shadow_state))
		return;

	/*
	 * Preserve the vtimer state so that it is always correct,
	 * even if the host tries to make a mess.
	 */
	__vcpu_sys_reg(shadow_vcpu, CNTV_CVAL_EL0) = read_sysreg_el0(SYS_CNTV_CVAL);
	__vcpu_sys_reg(shadow_vcpu, CNTV_CTL_EL0) = read_sysreg_el0(SYS_CNTV_CTL);
}

static void __copy_vcpu_state(const struct kvm_vcpu *from_vcpu,
			      struct kvm_vcpu *to_vcpu)
{
	int i;

	to_vcpu->arch.ctxt.regs		= from_vcpu->arch.ctxt.regs;
	to_vcpu->arch.ctxt.spsr_abt	= from_vcpu->arch.ctxt.spsr_abt;
	to_vcpu->arch.ctxt.spsr_und	= from_vcpu->arch.ctxt.spsr_und;
	to_vcpu->arch.ctxt.spsr_irq	= from_vcpu->arch.ctxt.spsr_irq;
	to_vcpu->arch.ctxt.spsr_fiq	= from_vcpu->arch.ctxt.spsr_fiq;

	/*
	 * Copy the sysregs, but don't mess with the timer state which
	 * is directly handled by EL1 and is expected to be preserved.
	 */
	for (i = 1; i < NR_SYS_REGS; i++) {
		if (i >= CNTVOFF_EL2 && i <= CNTP_CTL_EL0)
			continue;
		to_vcpu->arch.ctxt.sys_regs[i] = from_vcpu->arch.ctxt.sys_regs[i];
	}
}

static void __sync_vcpu_state(struct kvm_shadow_vcpu_state *shadow_state)
{
	__copy_vcpu_state(&shadow_state->shadow_vcpu, shadow_state->host_vcpu);
}

static void __flush_vcpu_state(struct kvm_shadow_vcpu_state *shadow_state)
{
	__copy_vcpu_state(shadow_state->host_vcpu, &shadow_state->shadow_vcpu);
}

static void flush_shadow_state(struct kvm_shadow_vcpu_state *shadow_state)
{
	struct kvm_vcpu *shadow_vcpu = &shadow_state->shadow_vcpu;
	struct kvm_vcpu *host_vcpu = shadow_state->host_vcpu;
	shadow_entry_exit_handler_fn ec_handler;
	u8 esr_ec;

	/*
	 * If we deal with a non-protected guest and the state is potentially
	 * dirty (from a host perspective), copy the state back into the shadow.
	 */
	if (!shadow_state_is_protected(shadow_state)) {
		if (vcpu_get_flag(host_vcpu, PKVM_HOST_STATE_DIRTY))
			__flush_vcpu_state(shadow_state);

		shadow_vcpu->arch.sve_state = kern_hyp_va(host_vcpu->arch.sve_state);
		shadow_vcpu->arch.sve_max_vl = host_vcpu->arch.sve_max_vl;

		shadow_vcpu->arch.hcr_el2 = HCR_GUEST_FLAGS & ~(HCR_RW | HCR_TWI | HCR_TWE);
		shadow_vcpu->arch.hcr_el2 |= READ_ONCE(host_vcpu->arch.hcr_el2);

		shadow_vcpu->arch.mdcr_el2 = host_vcpu->arch.mdcr_el2;
		shadow_vcpu->arch.debug_ptr = kern_hyp_va(host_vcpu->arch.debug_ptr);
	}

	shadow_vcpu->arch.vsesr_el2 = host_vcpu->arch.vsesr_el2;

	flush_vgic_state(host_vcpu, shadow_vcpu);
	flush_timer_state(shadow_state);

	switch (ARM_EXCEPTION_CODE(shadow_state->exit_code)) {
	case ARM_EXCEPTION_IRQ:
	case ARM_EXCEPTION_EL1_SERROR:
	case ARM_EXCEPTION_IL:
		break;
	case ARM_EXCEPTION_TRAP:
		esr_ec = ESR_ELx_EC(kvm_vcpu_get_esr(shadow_vcpu));
		ec_handler = entry_vm_shadow_handlers[esr_ec];
		if (ec_handler)
			ec_handler(host_vcpu, shadow_vcpu);
		break;
	default:
		BUG();
	}

	shadow_state->exit_code = 0;
}

static void sync_shadow_state(struct kvm_shadow_vcpu_state *shadow_state,
			      u32 exit_reason)
{
	struct kvm_vcpu *shadow_vcpu = &shadow_state->shadow_vcpu;
	struct kvm_vcpu *host_vcpu = shadow_state->host_vcpu;
	shadow_entry_exit_handler_fn ec_handler;
	u8 esr_ec;

	/*
	 * Don't sync the vcpu GPR/sysreg state after a run. Instead,
	 * leave it in the shadow until someone actually requires it.
	 */
	sync_vgic_state(host_vcpu, shadow_vcpu);
	sync_timer_state(shadow_state);

	switch (ARM_EXCEPTION_CODE(exit_reason)) {
	case ARM_EXCEPTION_IRQ:
		break;
	case ARM_EXCEPTION_TRAP:
		esr_ec = ESR_ELx_EC(kvm_vcpu_get_esr(shadow_vcpu));
		ec_handler = exit_vm_shadow_handlers[esr_ec];
		if (ec_handler)
			ec_handler(host_vcpu, shadow_vcpu);
		break;
	case ARM_EXCEPTION_EL1_SERROR:
	case ARM_EXCEPTION_IL:
		break;
	default:
		BUG();
	}

	vcpu_clear_flag(host_vcpu, PC_UPDATE_REQ);
	shadow_state->exit_code = exit_reason;
}

static void fpsimd_host_restore(void)
{
	sysreg_clear_set(cptr_el2, CPTR_EL2_TZ | CPTR_EL2_TFP, 0);
	isb();

	if (unlikely(is_protected_kvm_enabled())) {
		struct kvm_shadow_vcpu_state *shadow_state = pkvm_loaded_shadow_vcpu_state();
		struct kvm_vcpu *shadow_vcpu = &shadow_state->shadow_vcpu;
		struct user_fpsimd_state *host_fpsimd_state = this_cpu_ptr(&loaded_host_fpsimd_state);

		__fpsimd_save_state(&shadow_vcpu->arch.ctxt.fp_regs);
		__fpsimd_restore_state(host_fpsimd_state);

		shadow_vcpu->arch.fp_state = FP_STATE_HOST_OWNED;
	}

	if (system_supports_sve())
		sve_cond_update_zcr_vq(ZCR_ELx_LEN_MASK, SYS_ZCR_EL2);
}

static void handle___pkvm_vcpu_load(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(unsigned int, shadow_handle, host_ctxt, 1);
	DECLARE_REG(unsigned int, vcpu_idx, host_ctxt, 2);
	DECLARE_REG(u64, hcr_el2, host_ctxt, 3);
	struct kvm_shadow_vcpu_state *shadow_state;
	struct kvm_vcpu *shadow_vcpu;
	int *last_ran;

	if (!is_protected_kvm_enabled())
		return;

	shadow_state = pkvm_load_shadow_vcpu_state(shadow_handle, vcpu_idx);
	if (!shadow_state)
		return;

	shadow_vcpu = &shadow_state->shadow_vcpu;

	/*
	 * Guarantee that both TLBs and I-cache are private to each vcpu. If a
	 * vcpu from the same VM has previously run on the same physical CPU,
	 * nuke the relevant contexts.
	 */
	last_ran = &shadow_vcpu->arch.hw_mmu->last_vcpu_ran[hyp_smp_processor_id()];
	if (*last_ran != shadow_vcpu->vcpu_id) {
		__kvm_flush_cpu_context(shadow_vcpu->arch.hw_mmu);
		*last_ran = shadow_vcpu->vcpu_id;
	}

	shadow_vcpu->arch.host_fpsimd_state = this_cpu_ptr(&loaded_host_fpsimd_state);
	shadow_vcpu->arch.fp_state = FP_STATE_HOST_OWNED;

	if (shadow_state_is_protected(shadow_state)) {
		/* Propagate WFx trapping flags, trap ptrauth */
		shadow_vcpu->arch.hcr_el2 &= ~(HCR_TWE | HCR_TWI |
					       HCR_API | HCR_APK);
		shadow_vcpu->arch.hcr_el2 |= hcr_el2 & (HCR_TWE | HCR_TWI);
	}
}

static void handle___pkvm_vcpu_put(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_shadow_vcpu_state *shadow_state;

	if (!is_protected_kvm_enabled())
		return;

	shadow_state = pkvm_loaded_shadow_vcpu_state();

	if (shadow_state) {
		struct kvm_vcpu *host_vcpu = shadow_state->host_vcpu;
		struct kvm_vcpu *shadow_vcpu = &shadow_state->shadow_vcpu;

		if (shadow_vcpu->arch.fp_state == FP_STATE_GUEST_OWNED)
			fpsimd_host_restore();

		if (!shadow_state_is_protected(shadow_state) &&
		    !vcpu_get_flag(host_vcpu, PKVM_HOST_STATE_DIRTY))
			__sync_vcpu_state(shadow_state);

		pkvm_put_shadow_vcpu_state(shadow_state);
	}
}

static void handle___pkvm_vcpu_sync_state(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_shadow_vcpu_state *shadow_state;

	if (!is_protected_kvm_enabled())
		return;

	shadow_state = pkvm_loaded_shadow_vcpu_state();

	if (!shadow_state || shadow_state_is_protected(shadow_state))
		return;

	__sync_vcpu_state(shadow_state);
}

static struct kvm_vcpu *__get_current_vcpu(struct kvm_vcpu *vcpu,
					   struct kvm_shadow_vcpu_state **state)
{
	struct kvm_shadow_vcpu_state *sstate = NULL;

	vcpu = kern_hyp_va(vcpu);

	if (unlikely(is_protected_kvm_enabled())) {
		sstate = pkvm_loaded_shadow_vcpu_state();
		if (!sstate || vcpu != sstate->host_vcpu) {
			sstate = NULL;
			vcpu = NULL;
		}
	}

	*state = sstate;
	return vcpu;
}

#define get_current_vcpu(ctxt, regnr, statepp)				\
	({								\
		DECLARE_REG(struct kvm_vcpu *, __vcpu, ctxt, regnr);	\
		__get_current_vcpu(__vcpu, statepp);			\
	})

static void handle___kvm_vcpu_run(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_shadow_vcpu_state *shadow_state;
	struct kvm_vcpu *vcpu;
	int ret;

	vcpu = get_current_vcpu(host_ctxt, 1, &shadow_state);
	if (!vcpu) {
		cpu_reg(host_ctxt, 1) =  -EINVAL;
		return;
	}

	if (unlikely(shadow_state)) {
		flush_shadow_state(shadow_state);

		ret = __kvm_vcpu_run(&shadow_state->shadow_vcpu);

		sync_shadow_state(shadow_state, ret);

		if (shadow_state->shadow_vcpu.arch.fp_state == FP_STATE_GUEST_OWNED) {
			/*
			 * The guest has used the FP, trap all accesses
			 * from the host (both FP and SVE).
			 */
			u64 reg = CPTR_EL2_TFP;

			if (system_supports_sve())
				reg |= CPTR_EL2_TZ;

			sysreg_clear_set(cptr_el2, 0, reg);
		}
	} else {
		ret = __kvm_vcpu_run(vcpu);
	}

	cpu_reg(host_ctxt, 1) =  ret;
}

static int pkvm_refill_memcache(struct kvm_vcpu *shadow_vcpu,
				struct kvm_vcpu *host_vcpu)
{
	struct kvm_shadow_vcpu_state *shadow_vcpu_state = get_shadow_state(shadow_vcpu);
	u64 nr_pages = VTCR_EL2_LVLS(shadow_vcpu_state->shadow_vm->kvm.arch.vtcr) - 1;

	return refill_memcache(&shadow_vcpu->arch.pkvm_memcache, nr_pages,
			       &host_vcpu->arch.pkvm_memcache);
}

static void handle___pkvm_host_map_guest(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pfn, host_ctxt, 1);
	DECLARE_REG(u64, gfn, host_ctxt, 2);
	struct kvm_vcpu *host_vcpu;
	struct kvm_vcpu *shadow_vcpu;
	struct kvm_shadow_vcpu_state *shadow_state;
	int ret = -EINVAL;

	if (!is_protected_kvm_enabled())
		goto out;

	shadow_state = pkvm_loaded_shadow_vcpu_state();
	if (!shadow_state)
		goto out;

	host_vcpu = shadow_state->host_vcpu;
	shadow_vcpu = &shadow_state->shadow_vcpu;

	/* Topup shadow memcache with the host's */
	ret = pkvm_refill_memcache(shadow_vcpu, host_vcpu);
	if (ret)
		goto out;

	if (shadow_state_is_protected(shadow_state))
		ret = __pkvm_host_donate_guest(pfn, gfn, shadow_vcpu);
	else
		ret = __pkvm_host_share_guest(pfn, gfn, shadow_vcpu);
out:
	cpu_reg(host_ctxt, 1) =  ret;
}

static void handle___kvm_adjust_pc(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_shadow_vcpu_state *shadow_state;
	struct kvm_vcpu *vcpu;

	vcpu = get_current_vcpu(host_ctxt, 1, &shadow_state);
	if (!vcpu)
		return;

	if (shadow_state) {
		/* This only applies to non-protected VMs */
		if (shadow_state_is_protected(shadow_state))
			return;

		vcpu = &shadow_state->shadow_vcpu;
	}

	__kvm_adjust_pc(vcpu);
}

static void handle___kvm_flush_vm_context(struct kvm_cpu_context *host_ctxt)
{
	__kvm_flush_vm_context();
}

static void handle___kvm_tlb_flush_vmid_ipa(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);
	DECLARE_REG(phys_addr_t, ipa, host_ctxt, 2);
	DECLARE_REG(int, level, host_ctxt, 3);

	__kvm_tlb_flush_vmid_ipa(kern_hyp_va(mmu), ipa, level);
}

static void handle___kvm_tlb_flush_vmid(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);

	__kvm_tlb_flush_vmid(kern_hyp_va(mmu));
}

static void handle___kvm_flush_cpu_context(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);

	__kvm_flush_cpu_context(kern_hyp_va(mmu));
}

static void handle___kvm_timer_set_cntvoff(struct kvm_cpu_context *host_ctxt)
{
	__kvm_timer_set_cntvoff(cpu_reg(host_ctxt, 1));
}

static void handle___kvm_enable_ssbs(struct kvm_cpu_context *host_ctxt)
{
	u64 tmp;

	tmp = read_sysreg_el2(SYS_SCTLR);
	tmp |= SCTLR_ELx_DSSBS;
	write_sysreg_el2(tmp, SYS_SCTLR);
}

static void handle___vgic_v3_get_gic_config(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __vgic_v3_get_gic_config();
}

static void handle___vgic_v3_init_lrs(struct kvm_cpu_context *host_ctxt)
{
	__vgic_v3_init_lrs();
}

static void handle___kvm_get_mdcr_el2(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __kvm_get_mdcr_el2();
}

static void handle___vgic_v3_save_vmcr_aprs(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct vgic_v3_cpu_if *, cpu_if, host_ctxt, 1);

	__vgic_v3_save_vmcr_aprs(kern_hyp_va(cpu_if));
}

static void handle___vgic_v3_restore_vmcr_aprs(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct vgic_v3_cpu_if *, cpu_if, host_ctxt, 1);

	__vgic_v3_restore_vmcr_aprs(kern_hyp_va(cpu_if));
}

static void handle___pkvm_init(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(phys_addr_t, phys, host_ctxt, 1);
	DECLARE_REG(unsigned long, size, host_ctxt, 2);
	DECLARE_REG(unsigned long, nr_cpus, host_ctxt, 3);
	DECLARE_REG(unsigned long *, per_cpu_base, host_ctxt, 4);
	DECLARE_REG(u32, hyp_va_bits, host_ctxt, 5);

	/*
	 * __pkvm_init() will return only if an error occurred, otherwise it
	 * will tail-call in __pkvm_init_finalise() which will have to deal
	 * with the host context directly.
	 */
	cpu_reg(host_ctxt, 1) = __pkvm_init(phys, size, nr_cpus, per_cpu_base,
					    hyp_va_bits);
}

static void handle___pkvm_cpu_set_vector(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(enum arm64_hyp_spectre_vector, slot, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = pkvm_cpu_set_vector(slot);
}

static void handle___pkvm_host_share_hyp(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pfn, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = __pkvm_host_share_hyp(pfn);
}

static void handle___pkvm_host_unshare_hyp(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pfn, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = __pkvm_host_unshare_hyp(pfn);
}

static void handle___pkvm_host_reclaim_page(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(u64, pfn, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = __pkvm_host_reclaim_page(pfn);
}

static void handle___pkvm_create_private_mapping(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(phys_addr_t, phys, host_ctxt, 1);
	DECLARE_REG(size_t, size, host_ctxt, 2);
	DECLARE_REG(enum kvm_pgtable_prot, prot, host_ctxt, 3);

	/*
	 * __pkvm_create_private_mapping() populates a pointer with the
	 * hypervisor start address of the allocation.
	 *
	 * However, handle___pkvm_create_private_mapping() hypercall crosses the
	 * EL1/EL2 boundary so the pointer would not be valid in this context.
	 *
	 * Instead pass the allocation address as the return value (or return
	 * ERR_PTR() on failure).
	 */
	unsigned long haddr;
	int err = __pkvm_create_private_mapping(phys, size, prot, &haddr);

	if (err)
		haddr = (unsigned long)ERR_PTR(err);

	cpu_reg(host_ctxt, 1) = haddr;
}

static void handle___pkvm_prot_finalize(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __pkvm_prot_finalize();
}

static void handle___pkvm_init_shadow(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm *, host_kvm, host_ctxt, 1);
	DECLARE_REG(unsigned long, host_shadow_va, host_ctxt, 2);
	DECLARE_REG(size_t, shadow_size, host_ctxt, 3);
	DECLARE_REG(unsigned long, pgd, host_ctxt, 4);
	DECLARE_REG(unsigned long, last_ran, host_ctxt, 5);
	DECLARE_REG(size_t, last_ran_size, host_ctxt, 6);

	cpu_reg(host_ctxt, 1) = __pkvm_init_shadow(host_kvm, host_shadow_va,
						   shadow_size, pgd,
						   last_ran, last_ran_size);
}

static void handle___pkvm_teardown_shadow(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(unsigned int, shadow_handle, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = __pkvm_teardown_shadow(shadow_handle);
}

typedef void (*hcall_t)(struct kvm_cpu_context *);

#define HANDLE_FUNC(x)	[__KVM_HOST_SMCCC_FUNC_##x] = (hcall_t)handle_##x

static const hcall_t host_hcall[] = {
	/* ___kvm_hyp_init */
	HANDLE_FUNC(__kvm_get_mdcr_el2),
	HANDLE_FUNC(__pkvm_init),
	HANDLE_FUNC(__pkvm_create_private_mapping),
	HANDLE_FUNC(__pkvm_cpu_set_vector),
	HANDLE_FUNC(__kvm_enable_ssbs),
	HANDLE_FUNC(__vgic_v3_init_lrs),
	HANDLE_FUNC(__vgic_v3_get_gic_config),
	HANDLE_FUNC(__pkvm_prot_finalize),

	HANDLE_FUNC(__pkvm_host_share_hyp),
	HANDLE_FUNC(__pkvm_host_unshare_hyp),
	HANDLE_FUNC(__pkvm_host_reclaim_page),
	HANDLE_FUNC(__pkvm_host_map_guest),
	HANDLE_FUNC(__kvm_adjust_pc),
	HANDLE_FUNC(__kvm_vcpu_run),
	HANDLE_FUNC(__kvm_flush_vm_context),
	HANDLE_FUNC(__kvm_tlb_flush_vmid_ipa),
	HANDLE_FUNC(__kvm_tlb_flush_vmid),
	HANDLE_FUNC(__kvm_flush_cpu_context),
	HANDLE_FUNC(__kvm_timer_set_cntvoff),
	HANDLE_FUNC(__vgic_v3_save_vmcr_aprs),
	HANDLE_FUNC(__vgic_v3_restore_vmcr_aprs),
	HANDLE_FUNC(__pkvm_init_shadow),
	HANDLE_FUNC(__pkvm_teardown_shadow),
	HANDLE_FUNC(__pkvm_vcpu_load),
	HANDLE_FUNC(__pkvm_vcpu_put),
	HANDLE_FUNC(__pkvm_vcpu_sync_state),
};

static void handle_host_hcall(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(unsigned long, id, host_ctxt, 0);
	unsigned long hcall_min = 0;
	hcall_t hfn;

	/*
	 * If pKVM has been initialised then reject any calls to the
	 * early "privileged" hypercalls. Note that we cannot reject
	 * calls to __pkvm_prot_finalize for two reasons: (1) The static
	 * key used to determine initialisation must be toggled prior to
	 * finalisation and (2) finalisation is performed on a per-CPU
	 * basis. This is all fine, however, since __pkvm_prot_finalize
	 * returns -EPERM after the first call for a given CPU.
	 */
	if (static_branch_unlikely(&kvm_protected_mode_initialized))
		hcall_min = __KVM_HOST_SMCCC_FUNC___pkvm_prot_finalize;

	id -= KVM_HOST_SMCCC_ID(0);

	if (unlikely(id < hcall_min || id >= ARRAY_SIZE(host_hcall)))
		goto inval;

	hfn = host_hcall[id];
	if (unlikely(!hfn))
		goto inval;

	cpu_reg(host_ctxt, 0) = SMCCC_RET_SUCCESS;
	hfn(host_ctxt);

	return;
inval:
	cpu_reg(host_ctxt, 0) = SMCCC_RET_NOT_SUPPORTED;
}

static void default_host_smc_handler(struct kvm_cpu_context *host_ctxt)
{
	__kvm_hyp_host_forward_smc(host_ctxt);
}

static void handle_host_smc(struct kvm_cpu_context *host_ctxt)
{
	bool handled;

	handled = kvm_host_psci_handler(host_ctxt);
	if (!handled)
		default_host_smc_handler(host_ctxt);

	/* SMC was trapped, move ELR past the current PC. */
	kvm_skip_host_instr();
}

void handle_trap(struct kvm_cpu_context *host_ctxt)
{
	u64 esr = read_sysreg_el2(SYS_ESR);

	switch (ESR_ELx_EC(esr)) {
	case ESR_ELx_EC_HVC64:
		handle_host_hcall(host_ctxt);
		break;
	case ESR_ELx_EC_SMC64:
		handle_host_smc(host_ctxt);
		break;
	case ESR_ELx_EC_FP_ASIMD:
	case ESR_ELx_EC_SVE:
		fpsimd_host_restore();
		break;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		handle_host_mem_abort(host_ctxt);
		break;
	default:
		BUG();
	}
}
