// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: Quentin Perret <qperret@google.com>
 */

#include <nvhe/memory.h>

#include <linux/pgtable.h>
#include <asm/sections.h>

#include <nvhe/early_alloc.h>
#include <nvhe/mmu.h>

#define kvm_err(arg)
#undef VM_BUG_ON
#define VM_BUG_ON(arg)
#undef BUG_ON
#define BUG_ON(arg)
#include <hyp/mappings.h>

#ifndef __PAGETABLE_PUD_FOLDED
void pud_clear_bad(pud_t *pud)
{
	// XXX
	//pud_ERROR(*pud);
	pud_clear(pud);
}
#endif

#define hyp_pgd_order get_order(PTRS_PER_PGD * sizeof(pgd_t))

/* XXX - NR_CPUS */
void *kvm_hyp_stacks[CONFIG_NR_CPUS];

phys_addr_t __phys_hyp_pgd;
pgd_t* __hyp_pgd;

s64 hyp_physvirt_offset;
u64 __io_map_base;
u64 __hyp_vmemmap;

static int __hyp_create_early_private_mapping(phys_addr_t phys_addr,
					     size_t size, unsigned long *haddr,
					     pgprot_t prot)
{
	unsigned long base;
	int ret = 0;

	size = PAGE_ALIGN(size + offset_in_page(phys_addr));
	base = __io_map_base;
	__io_map_base += size;

	/* Are we overflowing on the vmemmap ? */
	if (__io_map_base > __hyp_vmemmap)
		return -ENOMEM;

	/* XXX - extended idmap */
	ret = __create_hyp_mappings_locked(__hyp_pgd, PTRS_PER_PGD,  base,
					   base + size,
					   phys_addr >> PAGE_SHIFT,
					   prot);
	if (ret)
		goto out;

	*haddr = base + offset_in_page(phys_addr);

out:
	return ret;
}

static int __hyp_create_early_mappings(unsigned long start, unsigned long end,
				       pgprot_t prot)
{
	unsigned long virt_addr;
	phys_addr_t phys_addr;

	start = start & PAGE_MASK;
	end = PAGE_ALIGN(end);

	for (virt_addr = start; virt_addr < end; virt_addr += PAGE_SIZE) {
		int err;

		phys_addr = hyp_virt_to_phys((void *)virt_addr);
		err = __create_hyp_mappings_locked(__hyp_pgd, PTRS_PER_PGD,
					    virt_addr, virt_addr + PAGE_SIZE,
					    phys_addr >> PAGE_SHIFT,
					    prot);
		if (err)
			return err;
	}

	return 0;
}

static int hyp_create_early_mappings(char *start, char *end, pgprot_t prot)
{
	return __hyp_create_early_mappings((unsigned long)start,
					   (unsigned long)end,
					   prot);
}

/* XXX - this modifies the host's bss directly */
extern void *__kvm_bp_vect_base;
static inline int hyp_early_map_vectors(phys_addr_t bp_vect_pa)
{
	unsigned long addr;
	int ret;

	if (!bp_vect_pa)
		return 0;

	ret = __hyp_create_early_private_mapping(bp_vect_pa,
						 __BP_HARDEN_HYP_VECS_SZ,
						 &addr, PAGE_HYP_EXEC);
	if (ret)
		return ret;

	__kvm_bp_vect_base = (void*)addr;

	return 0;
}

static int hyp_create_early_idmap(void)
{
	unsigned long start, end;

	start = (unsigned long)__hyp_idmap_text_start;
	start = hyp_virt_to_phys((void *)start);
	start = ALIGN_DOWN(start, PAGE_SIZE);

	end = (unsigned long)__hyp_idmap_text_end;
	end = hyp_virt_to_phys((void *)end);
	end = ALIGN(end, PAGE_SIZE);

	/*
	 * One half of the VA space is reserved to linearly map portions of
	 * memory -- see va_layout.c for more details. The other half of the VA
	 * space contains the trampoline page, and needs some care. Split that
	 * second half in two and find the quarter of VA space not conflicting
	 * with the idmap to place the IOs and the vmemmap. IOs use the lower
	 * half of the quarter and the vmemmap the upper half.
	 */
	__io_map_base = start & BIT(VA_BITS_MIN - 2); /* XXX - use vabits_actual */
	__io_map_base ^= BIT(VA_BITS_MIN - 2);
	__hyp_vmemmap = __io_map_base | BIT(VA_BITS_MIN - 3);

	/* XXX - extended idmap */

	return __create_hyp_mappings_locked(__hyp_pgd, PTRS_PER_PGD, start,
					    end, start >> PAGE_SHIFT,
					    PAGE_HYP_EXEC);
}

static int hyp_early_back_vmemmap(phys_addr_t phys, unsigned long size)
{
	unsigned long nr_pages = size >> PAGE_SHIFT;
	unsigned long start, end;
	struct hyp_page *p;
	phys_addr_t base;

	p = hyp_phys_to_page(phys);

	/* Find which portion of vmemmap needs to be backed up */
	start = (unsigned long)p;
	end = start + nr_pages * sizeof(struct hyp_page);
	start = ALIGN_DOWN(start, PAGE_SIZE);
	end = ALIGN(end, PAGE_SIZE);

	/* Allocate pages to back that portion */
	nr_pages = (end - start) >> PAGE_SHIFT;
	base = hyp_virt_to_phys(hyp_early_alloc_pages(0));
	if (!base)
		return -ENOMEM;
	nr_pages--;
	while (nr_pages) {
		if (!hyp_early_alloc_pages(0))
			return -ENOMEM;
		nr_pages--;
	}

	return __create_hyp_mappings_locked(__hyp_pgd, PTRS_PER_PGD, start,
					    end, base >> PAGE_SHIFT,
					    PAGE_HYP);
}

#define hyp_percpu_size ((unsigned long)__per_cpu_end - (unsigned long)__per_cpu_start)

int hyp_mm_early_pgtables(phys_addr_t phys, void* virt, unsigned long size,
			  phys_addr_t bp_vect_pa, unsigned long nr_cpus,
			  phys_addr_t *per_cpu_base)
{
	unsigned long base = (unsigned long)virt;
	void *stack;
	int err, i;
	u64 tmp_sp;

	if (phys % PAGE_SIZE || base % PAGE_SIZE || size % PAGE_SIZE)
		return -EINVAL;

	hyp_early_alloc_init(phys, base, size);
	__hyp_pgd = (pgd_t *)hyp_early_alloc_pages(hyp_pgd_order);
	if (!__hyp_pgd)
		return -ENOMEM;
	__phys_hyp_pgd = __hyp_pa(__hyp_pgd);

	/* XXX - EXTENDED IDMAP */

	err = hyp_create_early_idmap();
	if (err)
		return err;

	err = hyp_create_early_mappings(__hyp_text_start, __hyp_text_end, PAGE_HYP_EXEC);
	if (err)
		return err;

	err = hyp_create_early_mappings(__start_rodata, __end_rodata, PAGE_HYP_RO);
	if (err)
		return err;

	err = hyp_create_early_mappings(__bss_start, __bss_stop, PAGE_HYP_RO);
	if (err)
		return err;

	err = hyp_create_early_mappings(__hyp_bss_start, __hyp_bss_end, PAGE_HYP);
	if (err)
		return err;

	for (i = 0; i < nr_cpus; i++) {
		stack = hyp_early_alloc_pages(0);
		if (!stack)
			return -ENOMEM;
		err = hyp_create_early_mappings(stack, stack + 1, PAGE_HYP);
		if (err)
			return err;
		kvm_hyp_stacks[i] = stack;

		err = hyp_create_early_mappings(__hyp_va(per_cpu_base[i]),
				__hyp_va(per_cpu_base[i]) + PAGE_ALIGN(hyp_percpu_size),
				PAGE_HYP);
		if (err)
			return err;
	}

	err = __hyp_create_early_mappings(base, base + size - 1, PAGE_HYP);
	if (err)
		return err;

	err = hyp_early_back_vmemmap(phys, size);
	if (err)
		return err;

	err = hyp_early_map_vectors(bp_vect_pa);
	if (err)
		return err;

	/* XXX - switch SP instead */
	asm volatile ("mov %0, sp" : "=r"(tmp_sp) ::);
	err = __hyp_create_early_mappings(tmp_sp, tmp_sp + 1, PAGE_HYP);
	if (err)
		return err;

	return 0;
}

