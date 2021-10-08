// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pgtable.h>
#include <asm/stage2_pgtable.h>

#include <hyp/fault.h>

#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>

#define KVM_HOST_S2_FLAGS (KVM_PGTABLE_S2_NOFWB | KVM_PGTABLE_S2_IDMAP)

extern unsigned long hyp_nr_cpus;
struct pkvm_vm host_kvm;

/*
 * Copies of the host's CPU features registers holding sanitized values.
 */
u64 id_aa64mmfr0_el1_sys_val;
u64 id_aa64mmfr1_el1_sys_val;

const u8 pkvm_hyp_id = 1;

u32 max_phys_shift;

static void *host_s2_zalloc_pages_exact(size_t size)
{
	void *addr = hyp_alloc_pages(&host_kvm.pool, get_order(size));

	hyp_split_page(hyp_virt_to_page(addr));

	return addr;
}

static void *host_s2_zalloc_page(void *pool)
{
	return hyp_alloc_pages(pool, 0);
}

static void host_s2_get_page(void *addr)
{
	hyp_get_page(&host_kvm.pool, addr);
}

static void host_s2_put_page(void *addr)
{
	hyp_put_page(&host_kvm.pool, addr);
}

static int prepare_s2_pool(void *pgt_pool_base)
{
	unsigned long nr_pages, pfn;
	int ret;

	pfn = hyp_virt_to_pfn(pgt_pool_base);
	nr_pages = host_s2_pgtable_pages();
	ret = hyp_pool_init(&host_kvm.pool, pfn, nr_pages, 0);
	if (ret)
		return ret;

	host_kvm.mm_ops = (struct kvm_pgtable_mm_ops) {
		.zalloc_pages_exact = host_s2_zalloc_pages_exact,
		.zalloc_page = host_s2_zalloc_page,
		.phys_to_virt = hyp_phys_to_virt,
		.virt_to_phys = hyp_virt_to_phys,
		.page_count = hyp_page_count,
		.get_page = host_s2_get_page,
		.put_page = host_s2_put_page,
	};

	return 0;
}

static void prepare_host_vtcr(void)
{
	u32 parange;

	/* The host stage 2 is id-mapped, so use parange for T0SZ */
	parange = kvm_get_parange(id_aa64mmfr0_el1_sys_val);
	max_phys_shift = id_aa64mmfr0_parange_to_phys_shift(parange);

	host_kvm.arch.vtcr = kvm_get_vtcr(id_aa64mmfr0_el1_sys_val,
					  id_aa64mmfr1_el1_sys_val,
					  max_phys_shift);
}

static bool host_stage2_force_pte_cb(u64 addr, u64 end, enum kvm_pgtable_prot prot);

int kvm_host_prepare_stage2(void *pgt_pool_base)
{
	struct kvm_s2_mmu *mmu = &host_kvm.arch.mmu;
	int ret;

	prepare_host_vtcr();
	hyp_spin_lock_init(&host_kvm.lock);

	ret = prepare_s2_pool(pgt_pool_base);
	if (ret)
		return ret;

	ret = __kvm_pgtable_stage2_init(&host_kvm.pgt, &host_kvm.arch,
					&host_kvm.mm_ops, KVM_HOST_S2_FLAGS,
					host_stage2_force_pte_cb);
	if (ret)
		return ret;

	host_kvm.arch.pkvm_vm = &host_kvm;
	mmu->pgd_phys = __hyp_pa(host_kvm.pgt.pgd);
	mmu->arch = &host_kvm.arch;
	mmu->pgt = &host_kvm.pgt;
	WRITE_ONCE(mmu->vmid.vmid_gen, 0);
	WRITE_ONCE(mmu->vmid.vmid, 0);

	return 0;
}

int __pkvm_prot_finalize(void)
{
	struct kvm_s2_mmu *mmu = &host_kvm.arch.mmu;
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);

	params->vttbr = kvm_get_vttbr(mmu);
	params->vtcr = host_kvm.arch.vtcr;
	params->hcr_el2 |= HCR_VM;
	kvm_flush_dcache_to_poc(params, sizeof(*params));

	write_sysreg(params->hcr_el2, hcr_el2);
	__load_stage2(&host_kvm.arch.mmu, &host_kvm.arch);

	/*
	 * Make sure to have an ISB before the TLB maintenance below but only
	 * when __load_stage2() doesn't include one already.
	 */
	asm(ALTERNATIVE("isb", "nop", ARM64_WORKAROUND_SPECULATIVE_AT));

	/* Invalidate stale HCR bits that may be cached in TLBs */
	__tlbi(vmalls12e1);
	dsb(nsh);
	isb();

	return 0;
}

static int host_stage2_unmap_dev_all(void)
{
	struct kvm_pgtable *pgt = &host_kvm.pgt;
	struct memblock_region *reg;
	u64 addr = 0;
	int i, ret;

	/* Unmap all non-memory regions to recycle the pages */
	for (i = 0; i < hyp_memblock_nr; i++, addr = reg->base + reg->size) {
		reg = &hyp_memory[i];
		ret = kvm_pgtable_stage2_unmap(pgt, addr, reg->base - addr);
		if (ret)
			return ret;
	}
	return kvm_pgtable_stage2_unmap(pgt, addr, BIT(pgt->ia_bits) - addr);
}

struct kvm_mem_range {
	u64 start;
	u64 end;
};

static bool find_mem_range(phys_addr_t addr, struct kvm_mem_range *range)
{
	int cur, left = 0, right = hyp_memblock_nr;
	struct memblock_region *reg;
	phys_addr_t end;

	range->start = 0;
	range->end = ULONG_MAX;

	/* The list of memblock regions is sorted, binary search it */
	while (left < right) {
		cur = (left + right) >> 1;
		reg = &hyp_memory[cur];
		end = reg->base + reg->size;
		if (addr < reg->base) {
			right = cur;
			range->end = reg->base;
		} else if (addr >= end) {
			left = cur + 1;
			range->start = end;
		} else {
			range->start = reg->base;
			range->end = end;
			return true;
		}
	}

	return false;
}

bool addr_is_memory(phys_addr_t phys)
{
	struct kvm_mem_range range;

	return find_mem_range(phys, &range);
}

static bool is_in_mem_range(u64 addr, struct kvm_mem_range *range)
{
	return range->start <= addr && addr < range->end;
}

static bool range_is_memory(u64 start, u64 end)
{
	struct kvm_mem_range r;

	if (!find_mem_range(start, &r))
		return false;

	return is_in_mem_range(end - 1, &r);
}

static inline int __host_stage2_idmap(u64 start, u64 end,
				      enum kvm_pgtable_prot prot)
{
	return kvm_pgtable_stage2_map(&host_kvm.pgt, start, end - start, start,
				      prot, &host_kvm.pool);
}

/*
 * The pool has been provided with enough pages to cover all of memory with
 * page granularity, but it is difficult to know how much of the MMIO range
 * we will need to cover upfront, so we may need to 'recycle' the pages if we
 * run out.
 */
#define host_stage2_try(fn, ...)					\
	({								\
		int __ret;						\
		hyp_assert_lock_held(&host_kvm.lock);			\
		__ret = fn(__VA_ARGS__);				\
		if (__ret == -ENOMEM) {					\
			__ret = host_stage2_unmap_dev_all();		\
			if (!__ret)					\
				__ret = fn(__VA_ARGS__);		\
		}							\
		__ret;							\
	 })

static inline bool range_included(struct kvm_mem_range *child,
				  struct kvm_mem_range *parent)
{
	return parent->start <= child->start && child->end <= parent->end;
}

static int host_stage2_adjust_range(u64 addr, struct kvm_mem_range *range)
{
	struct kvm_mem_range cur;
	kvm_pte_t pte;
	u32 level;
	int ret;

	hyp_assert_lock_held(&host_kvm.lock);
	ret = kvm_pgtable_get_leaf(&host_kvm.pgt, addr, &pte, &level);
	if (ret)
		return ret;

	if (kvm_pte_valid(pte))
		return -EAGAIN;

	if (pte)
		return -EPERM;

	do {
		u64 granule = kvm_granule_size(level);
		cur.start = ALIGN_DOWN(addr, granule);
		cur.end = cur.start + granule;
		level++;
	} while ((level < KVM_PGTABLE_MAX_LEVELS) &&
			!(kvm_level_supports_block_mapping(level) &&
			  range_included(&cur, range)));

	*range = cur;

	return 0;
}

int host_stage2_idmap_locked(phys_addr_t addr, u64 size,
			     enum kvm_pgtable_prot prot)
{
	hyp_assert_lock_held(&host_kvm.lock);

	return host_stage2_try(__host_stage2_idmap, addr, addr + size, prot);
}

int host_stage2_set_owner_locked(phys_addr_t addr, u64 size, u8 owner_id)
{
	hyp_assert_lock_held(&host_kvm.lock);

	return host_stage2_try(kvm_pgtable_stage2_set_owner, &host_kvm.pgt,
			       addr, size, &host_kvm.pool, owner_id);
}

static bool host_stage2_force_pte_cb(u64 addr, u64 end, enum kvm_pgtable_prot prot)
{
	/*
	 * Block mappings must be used with care in the host stage-2 as a
	 * kvm_pgtable_stage2_map() operation targeting a page in the range of
	 * an existing block will delete the block under the assumption that
	 * mappings in the rest of the block range can always be rebuilt lazily.
	 * That assumption is correct for the host stage-2 with RWX mappings
	 * targeting memory or RW mappings targeting MMIO ranges (see
	 * host_stage2_idmap() below which implements some of the host memory
	 * abort logic). However, this is not safe for any other mappings where
	 * the host stage-2 page-table is in fact the only place where this
	 * state is stored. In all those cases, it is safer to use page-level
	 * mappings, hence avoiding to lose the state because of side-effects in
	 * kvm_pgtable_stage2_map().
	 */
	if (range_is_memory(addr, end))
		return prot != PKVM_HOST_MEM_PROT;
	else
		return prot != PKVM_HOST_MMIO_PROT;
}

static int host_stage2_idmap(u64 addr)
{
	struct kvm_mem_range range;
	bool is_memory = find_mem_range(addr, &range);
	enum kvm_pgtable_prot prot;
	int ret;

	prot = is_memory ? PKVM_HOST_MEM_PROT : PKVM_HOST_MMIO_PROT;

	hyp_spin_lock(&host_kvm.lock);
	ret = host_stage2_adjust_range(addr, &range);
	if (ret)
		goto unlock;

	ret = host_stage2_idmap_locked(range.start, range.end - range.start, prot);
unlock:
	hyp_spin_unlock(&host_kvm.lock);

	return ret;
}

/*
 * Valid page transitions are:
 *
 *	Name		Initiator			Recipient
 * 	----    	---------			---------
 *	DONATE		OWNED => FAULT			FAULT => OWNED
 *	SHARE		OWNED => SHARED_OWNED		FAULT => SHARED_BORROWED
 *	UNSHARE		SHARED_OWNED => OWNED		SHARED_BORROWED => FAULT
 *
 * VM teardown is a special case; pages are effectively wiped and donated back
 * to the host (we may do this lazily).
 *
 * FF-A introduces the following additional operations and states, which we
 * don't yet support:
 *
 *	LEND		OWNED => LENT_FAULT		FAULT => LENT_BORROWED
 *	RELINQUISH	LENT_BORROWED => FAULT		LENT_FAULT => LENT_OWNED
 *	RECLAIM		LENT_OWNED => OWNED		N/A
 */
enum pkvm_page_transition {
	PKVM_PAGE_DONATE,
	PKVM_PAGE_SHARE,
	PKVM_PAGE_UNSHARE,
};

/* This corresponds to locking order */
enum pkvm_component_id {
	PKVM_ID_HOST,
	PKVM_ID_HYP,
	PKVM_ID_GUEST,
};

struct pkvm_page_info {
	struct {
		enum pkvm_page_state			state;
		u64					addr;
	} requester;

	struct {
		enum pkvm_page_state			state;
		u64					addr;
	} receiver;

	phys_addr_t					phys;
};

struct pkvm_mem_req {
	u64						nr_pages;

	struct {
		enum pkvm_component_id			id;
		u64					addr;

		union {
			struct {
				u64			receiver_addr;
			} host;
		};
	} requester;

	struct {
		enum pkvm_component_id			id;

		struct {
			struct kvm			*kvm;
			struct kvm_hyp_memcache		*mc;
		} guest;
	} receiver;
};

struct pkvm_mem_donation {
	struct pkvm_mem_req	req;
};

struct pkvm_mem_share {
	struct pkvm_mem_req	req;
	enum kvm_pgtable_prot	prot;
};

/* Host */
static void host_lock_component(void)
{
	hyp_spin_lock(&host_kvm.lock);
}

static void host_unlock_component(void)
{
	hyp_spin_unlock(&host_kvm.lock);
}

static int host_get_page_state(enum pkvm_page_state *state, u64 addr)
{
	enum kvm_pgtable_prot prot;
	kvm_pte_t pte;
	int err;

	hyp_assert_lock_held(&host_kvm.lock);

	if (!addr_is_memory(addr))
		return -EFAULT;

	err = kvm_pgtable_get_leaf(&host_kvm.pgt, addr, &pte, NULL);
	if (err)
		return err;

	prot = kvm_pgtable_stage2_pte_prot(pte);
	*state = pkvm_getstate(prot);
	return 0;
}


static int __get_host_request_info(struct pkvm_page_info *info,
				   struct pkvm_mem_req *req,
				   u64 idx)
{
	u64 offset = idx * PAGE_SIZE;
	u64 host_addr = req->requester.addr + offset;
	u64 recv_addr = req->requester.host.receiver_addr + offset;

	*info = (struct pkvm_page_info) {
		.requester = {
			.addr = host_addr,
		},
		.receiver = {
			.addr = recv_addr,
		},
		.phys = host_addr,
	};

	return host_get_page_state(&info->requester.state, host_addr);
}

static int host_request_donation(struct pkvm_page_info *info,
				 struct pkvm_mem_donation *donation,
				 u64 idx)
{
	return __get_host_request_info(info, &donation->req, idx);
}

static int host_request_share(struct pkvm_page_info *info,
			      struct pkvm_mem_share *share,
			      u64 idx)
{
	return __get_host_request_info(info, &share->req, idx);
}

static int host_send_donation(struct pkvm_page_info *info,
			      enum pkvm_component_id receiver_id)
{
	return host_stage2_set_owner_locked(info->requester.addr, PAGE_SIZE,
					    receiver_id);
}

static int host_send_share(struct pkvm_page_info *info)
{
	enum kvm_pgtable_prot prot;

	prot = pkvm_mkstate(PKVM_HOST_MEM_PROT, PKVM_PAGE_SHARED_OWNED);
	return host_stage2_idmap_locked(info->requester.addr, PAGE_SIZE, prot);
}

/* Hyp */
static void hyp_lock_component(void)
{
	hyp_spin_lock(&pkvm_pgd_lock);
}

static void hyp_unlock_component(void)
{
	hyp_spin_unlock(&pkvm_pgd_lock);
}

static int hyp_get_page_state(enum pkvm_page_state *state, u64 addr)
{
	enum kvm_pgtable_prot prot;
	kvm_pte_t pte;
	int err;

	hyp_assert_lock_held(&pkvm_pgd_lock);
	err = kvm_pgtable_get_leaf(&pkvm_pgtable, addr, &pte, NULL);
	if (err)
		return err;

	prot = kvm_pgtable_hyp_pte_prot(pte);
	*state = pkvm_getstate(prot);
	return 0;
}

static int hyp_ack_donation(struct pkvm_page_info *info)
{
	return hyp_get_page_state(&info->receiver.state, info->receiver.addr);
}

static int hyp_ack_share(struct pkvm_page_info *info,
			 enum kvm_pgtable_prot perms)
{
	if (perms != PAGE_HYP)
		return -EPERM;

	return hyp_get_page_state(&info->receiver.state, info->receiver.addr);
}

static int hyp_recv_donation(struct pkvm_page_info *info,
			     enum pkvm_component_id requester_id)
{
	void *start = (void *)info->receiver.addr, *end = start + PAGE_SIZE;
	enum kvm_pgtable_prot prot;

	prot = pkvm_mkstate(PAGE_HYP, PKVM_PAGE_OWNED_OR_INVALID);
	return pkvm_create_mappings_locked(start, end, prot);
}

static int hyp_recv_share(struct pkvm_page_info *info,
			  enum kvm_pgtable_prot perms)
{
	void *start = (void *)info->receiver.addr, *end = start + PAGE_SIZE;
	enum kvm_pgtable_prot prot;

	prot = pkvm_mkstate(perms, PKVM_PAGE_SHARED_BORROWED);
	return pkvm_create_mappings_locked(start, end, prot);
}

/* Guest */
static void guest_lock_component(struct kvm *kvm)
{
	get_guest_vm(&kvm->arch);
}

static void guest_unlock_component(struct kvm *kvm)
{
	put_guest_vm(kvm->arch.pkvm_vm);
}

static int guest_get_page_state(enum pkvm_page_state *state, u64 addr,
				struct kvm *kvm)
{
	struct pkvm_vm *vm = kvm->arch.pkvm_vm;
	enum kvm_pgtable_prot prot;
	kvm_pte_t pte;
	int err;

	hyp_assert_lock_held(&vm->lock);
	err = kvm_pgtable_get_leaf(&vm->pgt, addr, &pte, NULL);
	if (err)
		return err;

	prot = kvm_pgtable_stage2_pte_prot(pte);
	*state = pkvm_getstate(prot);
	return 0;
}

static int guest_ack_share(struct pkvm_page_info *info,
			   enum kvm_pgtable_prot perms,
			   struct kvm *kvm)
{
	if (perms != KVM_PGTABLE_PROT_RWX)
		return -EPERM;

	return guest_get_page_state(&info->receiver.state, info->receiver.addr,
				    kvm);
}

static int guest_recv_share(struct pkvm_page_info *info,
			    enum kvm_pgtable_prot perms,
			    struct kvm *kvm,
			    struct kvm_hyp_memcache *mc)
{
	struct pkvm_vm *vm = kvm->arch.pkvm_vm;
	enum kvm_pgtable_prot prot;

	prot = pkvm_mkstate(perms, PKVM_PAGE_SHARED_BORROWED);
	return kvm_pgtable_stage2_map(&vm->pgt, info->receiver.addr, PAGE_SIZE,
				      info->phys, prot, mc);
}

static int request_donation(struct pkvm_page_info *info,
			    struct pkvm_mem_donation *donation,
			    u64 idx)
{
	struct pkvm_mem_req *req = &donation->req;

	switch (req->requester.id) {
	case PKVM_ID_HOST:
		return host_request_donation(info, donation, idx);
	default:
		return -EINVAL;
	}
}

static int ack_donation(struct pkvm_page_info *info,
			struct pkvm_mem_donation *donation)
{
	struct pkvm_mem_req *req = &donation->req;

	switch (req->receiver.id) {
	case PKVM_ID_HYP:
		return hyp_ack_donation(info);
	default:
		return -EINVAL;
	}
}

static int send_donation(struct pkvm_page_info *info,
			 struct pkvm_mem_donation *donation)
{
	struct pkvm_mem_req *req = &donation->req;

	switch (req->requester.id) {
	case PKVM_ID_HOST:
		return host_send_donation(info, req->receiver.id);
	default:
		return -EINVAL;
	}
}

static int recv_donation(struct pkvm_page_info *info,
			 struct pkvm_mem_donation *donation)
{
	struct pkvm_mem_req *req = &donation->req;

	switch (req->receiver.id) {
	case PKVM_ID_HYP:
		return hyp_recv_donation(info, req->requester.id);
	default:
		return -EINVAL;
	}
}

static int do_donate(struct pkvm_mem_donation *donation)
{
	struct pkvm_page_info info;
	int ret = 0;
	u64 idx;

	for (idx = 0; idx < donation->req.nr_pages; ++idx) {
		ret = request_donation(&info, donation, idx);
		if (ret)
			goto out;

		ret = ack_donation(&info, donation);
		if (ret)
			goto out;

		if (info.requester.state == PKVM_PAGE_OWNED_OR_INVALID &&
		    info.receiver.state == PKVM_PAGE_OWNED_OR_INVALID)
			continue;

		// XXX: We should get rid of this case as soon as we
		// unshare pages on guest termination
		if (info.requester.state == PKVM_PAGE_SHARED_OWNED &&
		    info.receiver.state == PKVM_PAGE_OWNED_OR_INVALID)
			continue;

		ret = -EPERM;
		goto out;
	}

	for (idx = 0; idx < donation->req.nr_pages; ++idx) {
		ret = request_donation(&info, donation, idx);
		if (ret)
			goto out_warn;

		ret = send_donation(&info, donation);
		if (ret)
			goto out_warn;

		ret = recv_donation(&info, donation);
		if (ret)
			goto out_warn;
	}

out_warn:
	WARN_ON(ret);
out:
	return ret;
}

static int request_share(struct pkvm_page_info *info,
			 struct pkvm_mem_share *share,
			 u64 idx)
{
	struct pkvm_mem_req *req = &share->req;

	switch (req->requester.id) {
	case PKVM_ID_HOST:
		return host_request_share(info, share, idx);
	default:
		return -EINVAL;
	}
}

static int ack_share(struct pkvm_page_info *info, struct pkvm_mem_share *share)
{
	struct pkvm_mem_req *req = &share->req;

	switch (req->receiver.id) {
	case PKVM_ID_HYP:
		return hyp_ack_share(info, share->prot);
	case PKVM_ID_GUEST:
		return guest_ack_share(info, share->prot,
				       req->receiver.guest.kvm);
	default:
		return -EINVAL;
	}
}

static int send_share(struct pkvm_page_info *info, struct pkvm_mem_share *share)
{
	struct pkvm_mem_req *req = &share->req;

	switch (req->requester.id) {
	case PKVM_ID_HOST:
		return host_send_share(info);
	default:
		return -EINVAL;
	}
}

static int recv_share(struct pkvm_page_info *info, struct pkvm_mem_share *share)
{
	struct pkvm_mem_req *req = &share->req;

	switch (req->receiver.id) {
	case PKVM_ID_HYP:
		return hyp_recv_share(info, share->prot);
	case PKVM_ID_GUEST:
		return guest_recv_share(info, share->prot,
					req->receiver.guest.kvm,
					req->receiver.guest.mc);
	default:
		return -EINVAL;
	}
}

static int do_share(struct pkvm_mem_share *share)
{
	struct pkvm_page_info info;
	int ret = 0;
	u64 idx;

	for (idx = 0; idx < share->req.nr_pages; ++idx) {
		ret = request_share(&info, share, idx);
		if (ret)
			goto out;

		ret = ack_share(&info, share);
		if (ret)
			goto out;

		if (info.requester.state == PKVM_PAGE_OWNED_OR_INVALID &&
		    info.receiver.state == PKVM_PAGE_OWNED_OR_INVALID)
			continue;

		if (info.requester.state == PKVM_PAGE_SHARED_OWNED &&
		    info.receiver.state == PKVM_PAGE_SHARED_BORROWED)
			continue;

		ret = -EPERM;
		goto out;
	}

	for (idx = 0; idx < share->req.nr_pages; ++idx) {
		ret = request_share(&info, share, idx);
		if (ret)
			goto out_warn;

		ret = ack_share(&info, share);
		if (ret)
			goto out;

		if (info.requester.state == PKVM_PAGE_SHARED_OWNED &&
		    info.receiver.state == PKVM_PAGE_SHARED_BORROWED)
			continue;

		ret = send_share(&info, share);
		if (ret)
			goto out_warn;

		ret = recv_share(&info, share);
		if (ret)
			goto out_warn;
	}

out_warn:
	WARN_ON(ret);
out:
	return ret;
}

int __pkvm_host_donate_hyp(u64 start_pfn, u64 end_pfn, bool host_locked)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(start_pfn);
	u64 hyp_addr = (u64)__hyp_va(host_addr);
	struct pkvm_mem_donation donation = {
		.req = {
			.nr_pages	= end_pfn - start_pfn,
			.requester	= {
				.id	= PKVM_ID_HOST,
				.addr	= host_addr,
				.host	= {
					.receiver_addr = hyp_addr,
				},
			},
			.receiver	= {
				.id	= PKVM_ID_HYP,
			},
		},
	};

	if (!host_locked)
		host_lock_component();
	hyp_lock_component();

	ret = do_donate(&donation);

	hyp_unlock_component();
	if (!host_locked)
		host_unlock_component();

	return ret;
}

int __pkvm_host_share_hyp(u64 pfn)
{
	int ret;
	u64 host_addr = hyp_pfn_to_phys(pfn);
	u64 hyp_addr = (u64)__hyp_va(host_addr);
	struct pkvm_mem_share share = {
		.req	= {
			.nr_pages	= 1,
			.requester	= {
				.id	= PKVM_ID_HOST,
				.addr	= host_addr,
				.host	= {
					.receiver_addr = hyp_addr,
				},
			},
			.receiver	= {
				.id	= PKVM_ID_HYP,
			},
		},
		.prot	= PAGE_HYP,
	};

	host_lock_component();
	hyp_lock_component();

	ret = do_share(&share);

	hyp_unlock_component();
	host_unlock_component();

	return ret;
}

int __pkvm_host_share_guest(u64 pfn, u64 ipa, struct kvm *kvm,
			    struct kvm_hyp_memcache *mc)
{
	int ret;
	struct pkvm_mem_share share = {
		.req	= {
			.nr_pages	= 1,
			.requester	= {
				.id	= PKVM_ID_HOST,
				.addr	= hyp_pfn_to_phys(pfn),
				.host	= {
					.receiver_addr = ipa,
				},
			},
			.receiver	= {
				.id	= PKVM_ID_GUEST,
				.guest	= {
					.kvm	= kvm,
					.mc	= mc,
				},
			},
		},
		.prot	= KVM_PGTABLE_PROT_RWX,
	};

	host_lock_component();
	guest_lock_component(kvm);

	ret = do_share(&share);

	guest_unlock_component(kvm);
	host_unlock_component();

	return ret;
}

void handle_host_mem_abort(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_vcpu_fault_info fault;
	u64 esr, addr;
	int ret = 0;

	esr = read_sysreg_el2(SYS_ESR);
	BUG_ON(!__get_fault_info(esr, &fault));

	addr = (fault.hpfar_el2 & HPFAR_MASK) << 8;
	ret = host_stage2_idmap(addr);
	BUG_ON(ret && ret != -EAGAIN);
}
