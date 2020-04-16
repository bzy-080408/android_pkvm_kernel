// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#ifndef __ARM64_KVM_HYP_TLB_H__
#define __ARM64_KVM_HYP_TLB_H__

#include <linux/irqflags.h>

#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/tlbflush.h>

struct tlb_inv_context {
	unsigned long	flags;
	u64		tcr;
	u64		sctlr;
};

static void __hyp_text __tlb_switch_to_guest(struct kvm *kvm,
					     struct tlb_inv_context *cxt);
static void __hyp_text __tlb_switch_to_host(struct kvm *kvm,
					    struct tlb_inv_context *cxt);

static inline void __hyp_text
__tlb_flush_vmid_ipa(struct kvm *kvm, phys_addr_t ipa)
{
	struct tlb_inv_context cxt;

	dsb(ishst);

	/* Switch to requested VMID */
	kvm = kern_hyp_va(kvm);
	__tlb_switch_to_guest(kvm, &cxt);

	/*
	 * We could do so much better if we had the VA as well.
	 * Instead, we invalidate Stage-2 for this IPA, and the
	 * whole of Stage-1. Weep...
	 */
	ipa >>= 12;
	__tlbi(ipas2e1is, ipa);

	/*
	 * We have to ensure completion of the invalidation at Stage-2,
	 * since a table walk on another CPU could refill a TLB with a
	 * complete (S1 + S2) walk based on the old Stage-2 mapping if
	 * the Stage-1 invalidation happened first.
	 */
	dsb(ish);
	__tlbi(vmalle1is);
	dsb(ish);
	isb();

	/*
	 * If the host is running at EL1 and we have a VPIPT I-cache,
	 * then we must perform I-cache maintenance at EL2 in order for
	 * it to have an effect on the guest. Since the guest cannot hit
	 * I-cache lines allocated with a different VMID, we don't need
	 * to worry about junk out of guest reset (we nuke the I-cache on
	 * VMID rollover), but we do need to be careful when remapping
	 * executable pages for the same guest. This can happen when KSM
	 * takes a CoW fault on an executable page, copies the page into
	 * a page that was previously mapped in the guest and then needs
	 * to invalidate the guest view of the I-cache for that page
	 * from EL1. To solve this, we invalidate the entire I-cache when
	 * unmapping a page from a guest if we have a VPIPT I-cache but
	 * the host is running at EL1. As above, we could do better if
	 * we had the VA.
	 *
	 * The moral of this story is: if you have a VPIPT I-cache, then
	 * you should be running with VHE enabled.
	 */
	if (!has_vhe() && icache_is_vpipt())
		__flush_icache_all();

	__tlb_switch_to_host(kvm, &cxt);
}

static inline void __hyp_text __tlb_flush_vmid(struct kvm *kvm)
{
	struct tlb_inv_context cxt;

	dsb(ishst);

	/* Switch to requested VMID */
	kvm = kern_hyp_va(kvm);
	__tlb_switch_to_guest(kvm, &cxt);

	__tlbi(vmalls12e1is);
	dsb(ish);
	isb();

	__tlb_switch_to_host(kvm, &cxt);
}

static inline void __hyp_text __tlb_flush_local_vmid(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = kern_hyp_va(kern_hyp_va(vcpu)->kvm);
	struct tlb_inv_context cxt;

	/* Switch to requested VMID */
	__tlb_switch_to_guest(kvm, &cxt);

	__tlbi(vmalle1);
	dsb(nsh);
	isb();

	__tlb_switch_to_host(kvm, &cxt);
}

static inline void __hyp_text __tlb_flush_vm_context(void)
{
	dsb(ishst);
	__tlbi(alle1is);

	/*
	 * VIPT and PIPT caches are not affected by VMID, so no maintenance
	 * is necessary across a VMID rollover.
	 *
	 * VPIPT caches constrain lookup and maintenance to the active VMID,
	 * so we need to invalidate lines with a stale VMID to avoid an ABA
	 * race after multiple rollovers.
	 *
	 */
	if (icache_is_vpipt())
		asm volatile("ic ialluis");

	dsb(ish);
}

#endif /* __ARM64_KVM_HYP_TLB_H__ */
