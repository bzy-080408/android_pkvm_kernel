/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#ifndef __KVM_NVHE_MEM_PROTECT__
#define __KVM_NVHE_MEM_PROTECT__
#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_pgtable.h>
#include <asm/virt.h>
#include <nvhe/gfp.h>
#include <nvhe/spinlock.h>

/*
 * SW bits 0-1 are reserved to track the memory ownership state of each page:
 *   00: The page is invalid or owned exclusively by the page-table owner.
 *   01: The page is owned by the page-table owner, but is shared
 *       with another entity.
 *   10: The page is shared with, but not owned by the page-table owner.
 *   11: Reserved for future use (lending).
 */
enum pkvm_page_state {
	PKVM_PAGE_OWNED_OR_INVALID	= 0ULL,
	PKVM_PAGE_SHARED_OWNED		= KVM_PGTABLE_PROT_SW0,
	PKVM_PAGE_SHARED_BORROWED	= KVM_PGTABLE_PROT_SW1,
};

#define PKVM_PAGE_STATE_PROT_MASK	(KVM_PGTABLE_PROT_SW0 | KVM_PGTABLE_PROT_SW1)
static inline enum kvm_pgtable_prot pkvm_mkstate(enum kvm_pgtable_prot prot,
						 enum pkvm_page_state state)
{
	return (prot & ~PKVM_PAGE_STATE_PROT_MASK) | state;
}

static inline enum pkvm_page_state pkvm_getstate(enum kvm_pgtable_prot prot)
{
	return prot & PKVM_PAGE_STATE_PROT_MASK;
}

struct pkvm_vm {
	struct kvm_arch arch;
	struct kvm_pgtable pgt;
	struct kvm_pgtable_mm_ops mm_ops;
	struct hyp_pool pool;
	hyp_spinlock_t lock;
};
extern struct pkvm_vm host_kvm;

extern const u8 pkvm_hyp_id;
extern u32 max_phys_shift;

int __pkvm_prot_finalize(void);
int __pkvm_host_share_hyp(u64 pfn);
int __pkvm_host_donate_hyp(u64 start_pfn, u64 end_pfn, bool host_locked);
int __pkvm_host_share_guest(u64 pfn, u64 ipa, struct kvm *kvm,
			    struct kvm_hyp_memcache *mc);

bool addr_is_memory(phys_addr_t phys);
int host_stage2_idmap_locked(phys_addr_t addr, u64 size, enum kvm_pgtable_prot prot);
int host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id);
int kvm_host_prepare_stage2(void *pgt_pool_base);
void handle_host_mem_abort(struct kvm_cpu_context *host_ctxt);

struct pkvm_vm *get_guest_vm(struct kvm_arch *arch);
void put_guest_vm(struct pkvm_vm *vm);

void pkvm_prepare_guests(void);
int pkvm_init_guest(struct kvm *kvm, u32 phys_shift, u64 pool_pfn, u64 nr_pages);
int pkvm_teardown_guest(struct kvm *kvm, struct kvm_hyp_memcache *mc);

static __always_inline void __load_host_stage2(void)
{
	if (static_branch_likely(&kvm_protected_mode_initialized))
		__load_stage2(&host_kvm.arch.mmu, &host_kvm.arch);
	else
		write_sysreg(0, vttbr_el2);
}

static inline void __load_guest_mmu(struct kvm_arch *arch)
{
	struct kvm_s2_mmu *mmu = &arch->mmu;

	if (static_branch_likely(&kvm_protected_mode_initialized))
		mmu = &arch->pkvm_vm->arch.mmu;
	__load_stage2(mmu, kern_hyp_va(mmu->arch));
}
#endif /* __KVM_NVHE_MEM_PROTECT__ */
