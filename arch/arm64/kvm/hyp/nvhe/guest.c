// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <asm/kvm_pgtable.h>
#include <linux/kvm_host.h>

#include <nvhe/gfp.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/spinlock.h>

/* XXX - move to header */
extern u64 id_aa64mmfr0_el1_sys_val;
extern u64 id_aa64mmfr1_el1_sys_val;

#define PKVM_NR_VMS	253

static struct pkvm_vm vms[PKVM_NR_VMS];
static DECLARE_BITMAP(vms_map, PKVM_NR_VMS);

static hyp_spinlock_t vms_lock;

static DEFINE_PER_CPU(struct pkvm_vm *, __cur_vm);
#define cur_vm_ptr (*this_cpu_ptr(&__cur_vm))

static void *guest_zalloc_page(void *memcache)
{
	struct hyp_page *p;
	void *addr;

	addr = hyp_alloc_pages(&cur_vm_ptr->pool, 0);
	if (addr)
		return addr;

	addr = hyp_admit_host_page(memcache);
	if (!addr)
		return addr;

	memset(addr, 0, PAGE_SIZE);

	/* XXX - use hyp_set_page_refcounted() instead ? */
	p = hyp_virt_to_page(addr);
	p->refcount = 1;

	return addr;
}

static void guest_get_page(void *addr)
{
	hyp_get_page(&cur_vm_ptr->pool, addr);
}

static void guest_put_page(void *addr)
{
	hyp_put_page(&cur_vm_ptr->pool, addr);
}

static void *guest_zalloc_pages_exact(size_t size)
{
	void *addr = hyp_alloc_pages(&cur_vm_ptr->pool, get_order(size));

	hyp_split_page(hyp_virt_to_page(addr));

	return addr;
}

static void guest_free_pages_exact(void *addr, size_t size)
{
	u8 order = get_order(size);
	unsigned int i;

	for (i = 0; i < (1 << order); i++)
		guest_put_page(addr + (i * PAGE_SIZE));
}

static unsigned long ffz_bitmap(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * BITS_PER_LONG < size; idx++) {
		if (addr[idx] != ~0UL)
			return min(idx * BITS_PER_LONG + ffz(addr[idx]), size);
	}

	return size;
}

static struct pkvm_vm *alloc_guest_vm(void)
{
	struct pkvm_vm *vm = NULL;
	unsigned int idx;

	hyp_spin_lock(&vms_lock);
	idx = ffz_bitmap(vms_map, PKVM_NR_VMS);
	if (idx < PKVM_NR_VMS) {
		vm = &vms[idx];
		__set_bit(idx, vms_map);
	}
	hyp_spin_unlock(&vms_lock);

	return vm;
}

static void free_guest_vm(struct pkvm_vm *vm)
{
	unsigned int idx = vm->arch.mmu.vmid.vmid - 2;

	hyp_spin_lock(&vms_lock);
	__clear_bit(idx, vms_map);
	hyp_spin_unlock(&vms_lock);
}

struct pkvm_vm *get_guest_vm(struct kvm_arch *arch)
{
	struct pkvm_vm *vm = arch->pkvm_vm;

	hyp_spin_lock(&vm->lock);
	cur_vm_ptr = vm;

	return vm;
}

void put_guest_vm(struct pkvm_vm *vm)
{
	hyp_spin_unlock(&vm->lock);
}

static int reclaim_walker(u64 addr, u64 end, u32 level, kvm_pte_t *ptep,
			      enum kvm_pgtable_walk_flags flag,
			      void * const arg)
{
	kvm_pte_t pte = *ptep;
	phys_addr_t phys;

	if (!kvm_pte_valid(pte))
		return 0;

	/*
	 * Only update the host stage-2 -- we're about to tear-down the guest
	 * stage-2 so no need to waste effort trying to keep it in sync.
	 */
	phys = kvm_pte_to_phys(pte);
	BUG_ON(host_stage2_set_owner_locked(phys, PAGE_SIZE, 0));
	/*
	 * XXX: if protected guest mark the page 'dirty' instead, and zero it
	 * lazily on host s2 aborts.
	 */

	return 0;
}

static void guest_reclaim_pages(struct pkvm_vm *vm)
{
	struct kvm_pgtable_walker walker = {
		.cb	= reclaim_walker,
		.flags	= KVM_PGTABLE_WALK_LEAF
	};
	hyp_assert_lock_held(&vm->lock);
	hyp_assert_lock_held(&host_kvm.lock);

	BUG_ON(kvm_pgtable_walk(&vm->pgt, 0, BIT(vm->pgt.ia_bits), &walker));
}

static void drain_guest_pool(struct pkvm_vm *vm, struct kvm_hyp_memcache *mc)
{
	void *cur = hyp_alloc_pages(&vm->pool, 0);
	struct hyp_page *page;

	while (cur) {
		page = hyp_virt_to_page(cur);
		memset(page, 0, sizeof(*page));
		hyp_return_host_page(mc, cur);
		cur = hyp_alloc_pages(&vm->pool, 0);
	}

}

int pkvm_teardown_guest(struct kvm *kvm, struct kvm_hyp_memcache *mc)
{
	struct pkvm_vm *vm;
	int ret = 0;

	hyp_spin_lock(&host_kvm.lock);
	vm = get_guest_vm(&kern_hyp_va(kvm)->arch);
	if (!vm) {
		ret = -EINVAL;
		goto host_unlock;
	}

	/* XXX - mark the guest unusable from that point. */

	guest_reclaim_pages(vm);
	kvm_pgtable_stage2_destroy(&vm->pgt);
	drain_guest_pool(vm, mc);

	free_guest_vm(vm);
	put_guest_vm(vm);
host_unlock:
	hyp_spin_unlock(&host_kvm.lock);

	return ret;
}

int pkvm_init_guest(struct kvm *kvm, u32 phys_shift, u64 pool_pfn, u64 nr_pages)
{
	struct pkvm_vm *vm;
	size_t pgd_sz;
	int ret;

	if (phys_shift > max_phys_shift || phys_shift < 32)
		return -EINVAL;

	/*
	 * We're only expecting the PGD to be passed in the memory pool, which
	 * the buddy allocator needs to have with order alignment.
	 */
	if (!IS_ALIGNED(pool_pfn, nr_pages))
		return -EINVAL;

	vm = alloc_guest_vm();
	if (!vm)
		return -ENOMEM;

	vm->arch.vtcr = kvm_get_vtcr(id_aa64mmfr0_el1_sys_val,
				     id_aa64mmfr1_el1_sys_val,
				     phys_shift);
	pgd_sz = kvm_pgtable_stage2_pgd_size(&vm->arch);
	if (pgd_sz > (nr_pages << PAGE_SHIFT)) {
		free_guest_vm(vm);
		return -ENOMEM;
	}

	ret = __pkvm_host_donate_hyp(pool_pfn, pool_pfn + nr_pages, false);
	if (ret) {
		free_guest_vm(vm);
		return ret;
	}

	ret = hyp_pool_init(&vm->pool, pool_pfn, nr_pages, 0);
	BUG_ON(ret);

	get_guest_vm(&vm->arch);
	ret = kvm_pgtable_stage2_init(&vm->pgt, &vm->arch, &vm->mm_ops);
	put_guest_vm(vm);
	BUG_ON(ret);
	vm->arch.mmu.pgd_phys = __hyp_pa(vm->pgt.pgd);

	/* XXX - don't store that here, use tabba@'s EL2 vm instead */
	kvm = kern_hyp_va(kvm);
	kvm->arch.pkvm_vm = vm;

	return ret;
}

void pkvm_prepare_guests(void)
{
	int i;

	for (i = 0; i < PKVM_NR_VMS; i++) {
		struct pkvm_vm *vm = &vms[i];
		struct kvm_s2_mmu *mmu = &vm->arch.mmu;

		vm->arch.pkvm_vm = vm;
		mmu->vmid.vmid = i + 2; /* a.k.a. owner_id: 0 for host, 1 for hyp */
		mmu->vmid.vmid_gen = 0; /* No rollover allowed, all belong to gen 0 */
		mmu->arch = &vm->arch;
		mmu->pgt = &vm->pgt;

		vm->mm_ops = (struct kvm_pgtable_mm_ops) {
			.zalloc_pages_exact = guest_zalloc_pages_exact,
			.free_pages_exact = guest_free_pages_exact,
			.zalloc_page = guest_zalloc_page,
			.phys_to_virt = hyp_phys_to_virt,
			.virt_to_phys = hyp_virt_to_phys,
			.page_count = hyp_page_count,
			.get_page = guest_get_page,
			.put_page = guest_put_page,
		};
	}
}
