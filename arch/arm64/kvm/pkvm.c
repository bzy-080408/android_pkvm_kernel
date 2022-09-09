// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <linux/memblock.h>
#include <linux/mutex.h>
#include <linux/sort.h>

#include <asm/kvm_pkvm.h>

#include "hyp_constants.h"

static struct memblock_region *hyp_memory = kvm_nvhe_sym(hyp_memory);
static unsigned int *hyp_memblock_nr_ptr = &kvm_nvhe_sym(hyp_memblock_nr);

phys_addr_t hyp_mem_base;
phys_addr_t hyp_mem_size;

static int cmp_hyp_memblock(const void *p1, const void *p2)
{
	const struct memblock_region *r1 = p1;
	const struct memblock_region *r2 = p2;

	return r1->base < r2->base ? -1 : (r1->base > r2->base);
}

static void __init sort_memblock_regions(void)
{
	sort(hyp_memory,
	     *hyp_memblock_nr_ptr,
	     sizeof(struct memblock_region),
	     cmp_hyp_memblock,
	     NULL);
}

static int __init register_memblock_regions(void)
{
	struct memblock_region *reg;

	for_each_mem_region(reg) {
		if (*hyp_memblock_nr_ptr >= HYP_MEMBLOCK_REGIONS)
			return -ENOMEM;

		hyp_memory[*hyp_memblock_nr_ptr] = *reg;
		(*hyp_memblock_nr_ptr)++;
	}
	sort_memblock_regions();

	return 0;
}

void __init kvm_hyp_reserve(void)
{
	u64 hyp_mem_pages = 0;
	int ret;

	if (!is_hyp_mode_available() || is_kernel_in_hyp_mode())
		return;

	if (kvm_get_mode() != KVM_MODE_PROTECTED)
		return;

	ret = register_memblock_regions();
	if (ret) {
		*hyp_memblock_nr_ptr = 0;
		kvm_err("Failed to register hyp memblocks: %d\n", ret);
		return;
	}

	hyp_mem_pages += hyp_s1_pgtable_pages();
	hyp_mem_pages += host_s2_pgtable_pages();
	hyp_mem_pages += hyp_shadow_table_pages();
	hyp_mem_pages += hyp_vmemmap_pages(STRUCT_HYP_PAGE_SIZE);

	/*
	 * Try to allocate a PMD-aligned region to reduce TLB pressure once
	 * this is unmapped from the host stage-2, and fallback to PAGE_SIZE.
	 */
	hyp_mem_size = hyp_mem_pages << PAGE_SHIFT;
	hyp_mem_base = memblock_phys_alloc(ALIGN(hyp_mem_size, PMD_SIZE),
					   PMD_SIZE);
	if (!hyp_mem_base)
		hyp_mem_base = memblock_phys_alloc(hyp_mem_size, PAGE_SIZE);
	else
		hyp_mem_size = ALIGN(hyp_mem_size, PMD_SIZE);

	if (!hyp_mem_base) {
		kvm_err("Failed to reserve hyp memory\n");
		return;
	}

	kvm_info("Reserved %lld MiB at 0x%llx\n", hyp_mem_size >> 20,
		 hyp_mem_base);
}

/*
 * Allocates and donates memory for EL2 shadow structs.
 *
 * Allocates space for the shadow state, which includes the shadow vm as well as
 * the shadow vcpu states.
 *
 * Stores an opaque handler in the kvm struct for future reference.
 *
 * Return 0 on success, negative error code on failure.
 */
static int __kvm_shadow_create(struct kvm *kvm)
{
	struct kvm_vcpu *vcpu, **vcpu_array;
	unsigned int shadow_handle;
	size_t pgd_sz, shadow_sz, vcpu_state_sz;
	void *pgd, *shadow_addr;
	unsigned long idx;
	int ret;

	if (kvm->created_vcpus < 1)
		return -EINVAL;

	pgd_sz = kvm_pgtable_stage2_pgd_size(kvm->arch.vtcr);
	/*
	 * The PGD pages will be reclaimed using a hyp_memcache which implies
	 * page granularity. So, use alloc_pages_exact() to get individual
	 * refcounts.
	 */
	pgd = alloc_pages_exact(pgd_sz, GFP_KERNEL_ACCOUNT);
	if (!pgd)
		return -ENOMEM;

	/* Allocate memory to donate to hyp for vm, and vcpu state pointers. */
	shadow_sz = PAGE_ALIGN(KVM_SHADOW_VM_SIZE +
			       sizeof(void *) * kvm->created_vcpus);
	shadow_addr = alloc_pages_exact(shadow_sz, GFP_KERNEL_ACCOUNT);
	if (!shadow_addr) {
		ret = -ENOMEM;
		goto free_pgd;
	}

	/* Stash the vcpu pointers into the PGD */
	BUILD_BUG_ON(KVM_MAX_VCPUS > (PAGE_SIZE / sizeof(u64)));
	vcpu_array = pgd;
	kvm_for_each_vcpu(idx, vcpu, kvm) {
		/* Indexing of the vcpus to be sequential starting at 0. */
		if (WARN_ON(vcpu->vcpu_idx != idx)) {
			ret = -EINVAL;
			goto free_shadow;
		}

		vcpu_array[idx] = vcpu;
	}

	/* Donate the shadow memory to hyp and let hyp initialize it. */
	ret = kvm_call_hyp_nvhe(__pkvm_init_shadow, kvm, shadow_addr, shadow_sz,
				pgd);
	if (ret < 0)
		goto free_shadow;

	shadow_handle = ret;

	/* Store the shadow handle given by hyp for future call reference. */
	kvm->arch.pkvm.shadow_handle = shadow_handle;
	kvm->arch.pkvm.hyp_donations.pgd = pgd;
	kvm->arch.pkvm.hyp_donations.shadow = shadow_addr;

	/* Donate memory for the vcpu state at hyp and initialize it. */
	vcpu_state_sz = PAGE_ALIGN(KVM_SHADOW_VCPU_STATE_SIZE);
	kvm_for_each_vcpu(idx, vcpu, kvm) {
		void *vcpu_state;

		/* Indexing of the vcpus to be sequential starting at 0. */
		if (WARN_ON(vcpu->vcpu_idx != idx)) {
			ret = -EINVAL;
			goto destroy_vm;
		}

		vcpu_state = alloc_pages_exact(vcpu_state_sz, GFP_KERNEL_ACCOUNT);
		if (!vcpu_state) {
			ret = -ENOMEM;
			goto destroy_vm;
		}

		ret = kvm_call_hyp_nvhe(__pkvm_init_shadow_vcpu,
					shadow_handle, vcpu, vcpu_state);
		if (ret) {
			free_pages_exact(vcpu_state, vcpu_state_sz);
			goto destroy_vm;
		}
	}

	return 0;

destroy_vm:
	kvm_shadow_destroy(kvm);
	return ret;
free_shadow:
	free_pages_exact(shadow_addr, shadow_sz);
free_pgd:
	free_pages_exact(pgd, pgd_sz);
	return ret;
}

int kvm_shadow_create(struct kvm *kvm)
{
	int ret = 0;

	mutex_lock(&kvm->arch.pkvm.shadow_lock);
	if (!kvm->arch.pkvm.shadow_handle)
		ret = __kvm_shadow_create(kvm);
	mutex_unlock(&kvm->arch.pkvm.shadow_lock);

	return ret;
}

void kvm_shadow_destroy(struct kvm *kvm)
{
	size_t pgd_sz, shadow_sz;

	if (kvm->arch.pkvm.shadow_handle)
		WARN_ON(kvm_call_hyp_nvhe(__pkvm_teardown_shadow,
					  kvm->arch.pkvm.shadow_handle));

	kvm->arch.pkvm.shadow_handle = 0;

	shadow_sz = PAGE_ALIGN(KVM_SHADOW_VM_SIZE +
			       KVM_SHADOW_VCPU_STATE_SIZE * kvm->created_vcpus);
	pgd_sz = kvm_pgtable_stage2_pgd_size(kvm->arch.vtcr);

	free_pages_exact(kvm->arch.pkvm.hyp_donations.shadow, shadow_sz);
	free_pages_exact(kvm->arch.pkvm.hyp_donations.pgd, pgd_sz);
}

int kvm_init_pvm(struct kvm *kvm)
{
	mutex_init(&kvm->arch.pkvm.shadow_lock);
	return 0;
}
