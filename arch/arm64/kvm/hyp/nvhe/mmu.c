// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: Quentin Perret <qperret@google.com>
 */

#include <nvhe/memory.h>

#include <linux/pgtable.h>
#include <asm/sections.h>

#include <nvhe/gfp.h>
#include <nvhe/mmu.h>

#define kvm_err(arg)
#undef VM_BUG_ON
#define VM_BUG_ON(arg)
#undef BUG_ON
#define BUG_ON(arg)
#include <hyp/mappings.h>

extern pgd_t* __hyp_pgd;
extern u64 __io_map_base;

nvhe_spinlock_t __hyp_pgd_lock;

int __kvm_hyp_create_mappings(unsigned long start, unsigned long end,
			      unsigned long pfn, unsigned long prot)
{
	pgprot_t __prot = { prot };
	int ret;

	nvhe_spin_lock(&__hyp_pgd_lock);
	ret = __create_hyp_mappings_locked(__hyp_pgd, PTRS_PER_PGD, start, end,
					   pfn, __prot);
	nvhe_spin_unlock(&__hyp_pgd_lock);

	return ret;
}

unsigned long __kvm_hyp_create_private_mapping(phys_addr_t phys_addr,
					       unsigned long size,
					       unsigned long prot)
{
	pgprot_t __prot = { prot };
	unsigned long base;
	int ret;

	nvhe_spin_lock(&__hyp_pgd_lock);

	size = PAGE_ALIGN(size + offset_in_page(phys_addr));
	base = __io_map_base;
	__io_map_base += size;

	/* Are we overflowing on the vmemmap ? */
	if (__io_map_base > __hyp_vmemmap) {
		base = 0; /* XXX - ERROR */
		goto out;
	}

	/* XXX - extended idmap */
	ret = __create_hyp_mappings_locked(__hyp_pgd, PTRS_PER_PGD,  base,
					   base + size, phys_addr >> PAGE_SHIFT,
					   __prot);
	if (ret)
		base = 0;

out:
	nvhe_spin_unlock(&__hyp_pgd_lock);

	return base;
}
