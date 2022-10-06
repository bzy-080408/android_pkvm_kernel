// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020 - Google LLC
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <linux/memblock.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/sort.h>

#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm.h>
#include <asm/kvm_pkvm_module.h>

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
	hyp_mem_pages += hyp_vm_table_pages();
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
 * Allocates and donates memory for hypervisor VM structs at EL2.
 *
 * Allocates space for the VM state, which includes the hyp vm as well as
 * the hyp vcpus.
 *
 * Stores an opaque handler in the kvm struct for future reference.
 *
 * Return 0 on success, negative error code on failure.
 */
static int __pkvm_create_hyp_vm(struct kvm *host_kvm)
{
	size_t pgd_sz, hyp_vm_sz, hyp_vcpu_sz, last_ran_sz;
	struct kvm_vcpu *host_vcpu;
	pkvm_handle_t handle;
	void *pgd, *hyp_vm, *last_ran;
	unsigned long idx;
	int ret;

	if (host_kvm->created_vcpus < 1)
		return -EINVAL;

	pgd_sz = kvm_pgtable_stage2_pgd_size(host_kvm->arch.vtcr);

	/*
	 * The PGD pages will be reclaimed using a hyp_memcache which implies
	 * page granularity. So, use alloc_pages_exact() to get individual
	 * refcounts.
	 */
	pgd = alloc_pages_exact(pgd_sz, GFP_KERNEL_ACCOUNT);
	if (!pgd)
		return -ENOMEM;

	/* Allocate memory to donate to hyp for vm and vcpu pointers. */
	hyp_vm_sz = PAGE_ALIGN(size_add(PKVM_HYP_VM_SIZE,
					size_mul(sizeof(void *),
						 host_kvm->created_vcpus)));
	hyp_vm = alloc_pages_exact(hyp_vm_sz, GFP_KERNEL_ACCOUNT);
	if (!hyp_vm) {
		ret = -ENOMEM;
		goto free_pgd;
	}

	/* Allocate memory to donate to hyp for tracking mmu->last_vcpu_ran. */
	last_ran_sz = PAGE_ALIGN(array_size(num_possible_cpus(), sizeof(int)));
	last_ran = alloc_pages_exact(last_ran_sz, GFP_KERNEL_ACCOUNT);
	if (!last_ran) {
		ret = -ENOMEM;
		goto free_vm;
	}

	/* Donate the VM memory to hyp and let hyp initialize it. */
	ret = kvm_call_hyp_nvhe(__pkvm_init_vm, host_kvm, hyp_vm, pgd, last_ran);
	if (ret < 0)
		goto free_last_ran;

	handle = ret;

	host_kvm->arch.pkvm.handle = handle;

	/* Donate memory for the vcpus at hyp and initialize it. */
	hyp_vcpu_sz = PAGE_ALIGN(PKVM_HYP_VCPU_SIZE);
	kvm_for_each_vcpu(idx, host_vcpu, host_kvm) {
		void *hyp_vcpu;

		/* Indexing of the vcpus to be sequential starting at 0. */
		if (WARN_ON(host_vcpu->vcpu_idx != idx)) {
			ret = -EINVAL;
			goto destroy_vm;
		}

		hyp_vcpu = alloc_pages_exact(hyp_vcpu_sz, GFP_KERNEL_ACCOUNT);
		if (!hyp_vcpu) {
			ret = -ENOMEM;
			goto destroy_vm;
		}

		ret = kvm_call_hyp_nvhe(__pkvm_init_vcpu, handle, host_vcpu,
					hyp_vcpu);
		if (ret) {
			free_pages_exact(hyp_vcpu, hyp_vcpu_sz);
			goto destroy_vm;
		}
	}

	return 0;

destroy_vm:
	pkvm_destroy_hyp_vm(host_kvm);
	return ret;
free_last_ran:
	free_pages_exact(last_ran, last_ran_sz);
free_vm:
	free_pages_exact(hyp_vm, hyp_vm_sz);
free_pgd:
	free_pages_exact(pgd, pgd_sz);
	return ret;
}

int pkvm_create_hyp_vm(struct kvm *host_kvm)
{
	int ret = 0;

	mutex_lock(&host_kvm->lock);
	if (!host_kvm->arch.pkvm.handle)
		ret = __pkvm_create_hyp_vm(host_kvm);
	mutex_unlock(&host_kvm->lock);

	return ret;
}

void pkvm_destroy_hyp_vm(struct kvm *host_kvm)
{
	struct kvm_pinned_page *ppage, *tmp;
	struct mm_struct *mm = current->mm;
	struct list_head *ppages;

	if (host_kvm->arch.pkvm.handle) {
		WARN_ON(kvm_call_hyp_nvhe(__pkvm_teardown_vm,
					  host_kvm->arch.pkvm.handle));
	}

	host_kvm->arch.pkvm.handle = 0;
	free_hyp_memcache(&host_kvm->arch.pkvm.teardown_mc);

	ppages = &host_kvm->arch.pkvm.pinned_pages;
	list_for_each_entry_safe(ppage, tmp, ppages, link) {
		WARN_ON(kvm_call_hyp_nvhe(__pkvm_host_reclaim_page,
					  page_to_pfn(ppage->page)));
		cond_resched();

		account_locked_vm(mm, 1, false);
		unpin_user_pages_dirty_lock(&ppage->page, 1, true);
		list_del(&ppage->link);
		kfree(ppage);
	}
}

int pkvm_init_host_vm(struct kvm *host_kvm, unsigned long type)
{
	mutex_init(&host_kvm->lock);

	if (!(type & KVM_VM_TYPE_ARM_PROTECTED))
		return 0;

	if (!is_protected_kvm_enabled())
		return -EINVAL;

	host_kvm->arch.pkvm.enabled = true;
	return 0;
}

struct pkvm_mod_sec_mapping {
	struct pkvm_module_section *sec;
	enum kvm_pgtable_prot prot;
};

static void pkvm_unmap_module_pages(void *kern_va, void *hyp_va, size_t size)
{
	size_t offset;
	u64 pfn;

	for (offset = 0; offset < size; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(kern_va + offset);
		kvm_call_hyp_nvhe(__pkvm_unmap_module_page, pfn,
				  hyp_va + offset);
	}
}

static void pkvm_unmap_module_sections(struct pkvm_mod_sec_mapping *secs_map, void *hyp_va_base, int nr_secs)
{
	size_t offset, size;
	void *start;
	int i;

	for (i = 0; i < nr_secs; i++) {
		start = secs_map[i].sec->start;
		size = secs_map[i].sec->end - start;
		offset = start - secs_map[0].sec->start;
		pkvm_unmap_module_pages(start, hyp_va_base + offset, size);
	}
}

static int pkvm_map_module_section(struct pkvm_mod_sec_mapping *sec_map, void *hyp_va)
{
	size_t offset, size = sec_map->sec->end - sec_map->sec->start;
	int ret;
	u64 pfn;

	for (offset = 0; offset < size; offset += PAGE_SIZE) {
		pfn = vmalloc_to_pfn(sec_map->sec->start + offset);
		ret = kvm_call_hyp_nvhe(__pkvm_map_module_page, pfn,
					hyp_va + offset, sec_map->prot);
		if (ret) {
			pkvm_unmap_module_pages(sec_map->sec->start, hyp_va, offset);
			return ret;
		}
	}

	return 0;
}

static int pkvm_map_module_sections(struct pkvm_mod_sec_mapping *secs_map, void *hyp_va_base, int nr_secs)
{
	size_t offset;
	int i, ret;

	for (i = 0; i < nr_secs; i++) {
		offset = secs_map[i].sec->start - secs_map[0].sec->start;
		ret = pkvm_map_module_section(&secs_map[i], hyp_va_base + offset);
		if (ret) {
			pkvm_unmap_module_sections(secs_map, hyp_va_base, i);
			return ret;
		}
	}

	return 0;
}

static int __pkvm_cmp_mod_sec(const void *p1, const void *p2)
{
	struct pkvm_mod_sec_mapping const *s1 = p1;
	struct pkvm_mod_sec_mapping const *s2 = p2;

	return s1->sec->start < s2->sec->start ? -1 : s1->sec->start > s2->sec->start;
}

int __pkvm_load_el2_module(struct pkvm_el2_module *mod, struct module *this)
{
	struct pkvm_mod_sec_mapping secs_map[] = {
		{ &mod->text, KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_X },
		{ &mod->bss, KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_W },
		{ &mod->rodata, KVM_PGTABLE_PROT_R },
		{ &mod->data, KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_W },
	};
	void *start, *end, *hyp_va;
	kvm_nvhe_reloc_t *endrel;
	size_t offset, size;
	int ret, i;

	if (!is_protected_kvm_enabled())
		return -EOPNOTSUPP;

	for (i = 0; i < ARRAY_SIZE(secs_map); i++) {
		if (!PAGE_ALIGNED(secs_map[i].sec->start)) {
			kvm_err("EL2 sections are not page-aligned\n");
			return -EINVAL;
		}
	}

	if (!try_module_get(this)) {
		kvm_err("Kernel module has been unloaded\n");
		return -ENODEV;
	}

	sort(secs_map, ARRAY_SIZE(secs_map), sizeof(secs_map[0]), __pkvm_cmp_mod_sec, NULL);
	start = secs_map[0].sec->start;
	end = secs_map[ARRAY_SIZE(secs_map) - 1].sec->end;
	size = PAGE_ALIGN(end - start);

	hyp_va = (void *)kvm_call_hyp_nvhe(__pkvm_alloc_module_va, size >> PAGE_SHIFT);
	if (!hyp_va) {
		kvm_err("Failed to allocate hypervisor VA space for EL2 module\n");
		module_put(this);
		return -ENOMEM;
	}
	endrel = (void *)mod->relocs + mod->nr_relocs * sizeof(*endrel);
	kvm_apply_hyp_module_relocations(start, hyp_va, mod->relocs, endrel);

	ret = pkvm_map_module_sections(secs_map, hyp_va, ARRAY_SIZE(secs_map));
	if (ret) {
		kvm_err("Failed to map EL2 module page: %d\n", ret);
		module_put(this);
		return ret;
	}

	offset = (size_t)((void *)mod->init - start);
	ret = kvm_call_hyp_nvhe(__pkvm_init_module, hyp_va + offset);
	if (ret) {
		kvm_err("Failed to init EL2 module: %d\n", ret);
		pkvm_unmap_module_sections(secs_map, hyp_va, ARRAY_SIZE(secs_map));
		module_put(this);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(__pkvm_load_el2_module);
