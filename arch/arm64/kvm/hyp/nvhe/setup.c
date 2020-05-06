// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>

#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/spinlock.h>

struct hyp_zone host_zone;

extern phys_addr_t __phys_hyp_pgd;
extern nvhe_spinlock_t __hyp_pgd_lock;

void __kvm_init_switch_pgd(phys_addr_t pgd);

int hyp_mm_early_pgtables(phys_addr_t phys, void* virt, unsigned long size,
			  phys_addr_t bp_vect_pa, unsigned long nr_cpus,
			  phys_addr_t *per_cpu_base);

unsigned long hyp_early_alloc_nr_pages(void);

int __kvm_hyp_setup(phys_addr_t phys, void* virt, unsigned long size,
		    phys_addr_t bp_vect_pa, unsigned long nr_cpus,
		    phys_addr_t *per_cpu_base)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	int (*fn)(long long unsigned int);
	int used_pages, ret;

	if (phys % PAGE_SIZE || size % PAGE_SIZE || (u64)virt % PAGE_SIZE)
		return -EINVAL;

	hyp_physvirt_offset = (s64)phys - (s64)virt;
	nvhe_spin_lock_init(&__hyp_pgd_lock);

	/* Recreate the page tables using the reserved hyp memory */
	ret = hyp_mm_early_pgtables(phys, virt, size, bp_vect_pa, nr_cpus,
			per_cpu_base);
	if (ret)
		return ret;
	used_pages = hyp_early_alloc_nr_pages();

	/* Jump in the idmap page to switch to the new page tables */
	fn = (typeof(fn))__hyp_pa(__kvm_init_switch_pgd);
	fn(__phys_hyp_pgd);

	/* Now that the vmemmap is backed, install the full-fledged allocator */
	hyp_zone_init(&host_zone);
	ret = hyp_zone_extend_used(&host_zone, phys, nr_pages, used_pages);
	if (ret)
		return ret;

	return 0;
}
