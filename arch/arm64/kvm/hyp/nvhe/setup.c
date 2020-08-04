// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: Quentin Perret <qperret@google.com>
 */

#include <linux/kvm_host.h>
#include <asm/kvm_hyp.h>

#include <nvhe/gfp.h>
#include <nvhe/memory.h>
#include <nvhe/mm.h>

struct hyp_zone host_zone;

void __noreturn kvm_hyp_loop(int ret);

void __noreturn __kvm_hyp_setup_finalise(phys_addr_t phys, unsigned long size)
{
	unsigned long nr_pages, used_pages;
	int ret;

	/* Now that the vmemmap is backed, install the full-fledged allocator */
	nr_pages = size >> PAGE_SHIFT;
	used_pages = hyp_early_alloc_nr_pages();

	hyp_zone_init(&host_zone);
	ret = hyp_zone_extend_used(&host_zone, phys, nr_pages, used_pages);
	kvm_hyp_loop(ret);
}

int __kvm_hyp_setup(phys_addr_t phys, void* virt, unsigned long size,
		    phys_addr_t bp_vect_pa, unsigned long nr_cpus,
		    phys_addr_t *per_cpu_base)
{
	int ret;
	void (*fn)(phys_addr_t, unsigned long, phys_addr_t, void *, void *);

	if (phys % PAGE_SIZE || size % PAGE_SIZE || (u64)virt % PAGE_SIZE)
		return -EINVAL;

	hyp_physvirt_offset = (s64)phys - (s64)virt;

	/* Recreate the page tables using the reserved hyp memory */
	ret = hyp_mm_early_pgtables(phys, virt, size, bp_vect_pa, nr_cpus,
				    per_cpu_base);
	if (ret)
		return ret;

	/* Jump in the idmap page to switch to the new page tables */
	fn = (typeof(fn))__hyp_pa(__kvm_init_switch_pgd);
	fn(phys, size, __phys_hyp_pgd, kvm_hyp_stacks[0],
	   __kvm_hyp_setup_finalise);

	unreachable();
}
