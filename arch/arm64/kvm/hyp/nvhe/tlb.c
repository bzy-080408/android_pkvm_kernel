// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/irqflags.h>

#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/tlbflush.h>

#include "../tlb.h"

static void __hyp_text __tlb_switch_to_guest(struct kvm *kvm,
					     struct tlb_inv_context *cxt)
{
	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		u64 val;

		/*
		 * For CPUs that are affected by ARM 1319367, we need to
		 * avoid a host Stage-1 walk while we have the guest's
		 * VMID set in the VTTBR in order to invalidate TLBs.
		 * We're guaranteed that the S1 MMU is enabled, so we can
		 * simply set the EPD bits to avoid any further TLB fill.
		 */
		val = cxt->tcr = read_sysreg_el1(SYS_TCR);
		val |= TCR_EPD1_MASK | TCR_EPD0_MASK;
		write_sysreg_el1(val, SYS_TCR);
		isb();
	}

	/* __load_guest_stage2() includes an ISB for the workaround. */
	__load_guest_stage2(kvm);
	asm(ALTERNATIVE("isb", "nop", ARM64_WORKAROUND_SPECULATIVE_AT));
}

static void __hyp_text __tlb_switch_to_host(struct kvm *kvm,
					    struct tlb_inv_context *cxt)
{
	write_sysreg(0, vttbr_el2);

	if (cpus_have_final_cap(ARM64_WORKAROUND_SPECULATIVE_AT)) {
		/* Ensure write of the host VMID */
		isb();
		/* Restore the host's TCR_EL1 */
		write_sysreg_el1(cxt->tcr, SYS_TCR);
	}
}

void __hyp_text __kvm_tlb_flush_vmid_ipa(struct kvm *kvm, phys_addr_t ipa)
{
	__tlb_flush_vmid_ipa(kvm, ipa);
}

void __hyp_text __kvm_tlb_flush_vmid(struct kvm *kvm)
{
	__tlb_flush_vmid(kvm);
}

void __hyp_text __kvm_tlb_flush_local_vmid(struct kvm_vcpu *vcpu)
{
	__tlb_flush_local_vmid(vcpu);
}

void __hyp_text __kvm_flush_vm_context(void)
{
	__tlb_flush_vm_context();
}
