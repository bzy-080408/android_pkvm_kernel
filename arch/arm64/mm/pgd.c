// SPDX-License-Identifier: GPL-2.0-only
/*
 * PGD allocation/freeing
 *
 * Copyright (C) 2012 ARM Ltd.
 * Author: Catalin Marinas <catalin.marinas@arm.com>
 */

#include <linux/mm.h>
#include <linux/gfp.h>
#include <linux/highmem.h>
#include <linux/slab.h>

#include <asm/pgalloc.h>
#include <asm/page.h>
#include <asm/tlbflush.h>

static struct kmem_cache *pgd_cache __ro_after_init;
static DEFINE_RAW_SPINLOCK(patch_pte_lock);

DEFINE_STATIC_KEY_FALSE(ro_page_tables);

pgd_t *pgd_alloc(struct mm_struct *mm)
{
	gfp_t gfp = GFP_PGTABLE_USER;

	if (PGD_SIZE == PAGE_SIZE)
		return (pgd_t *)__get_free_page(gfp);
	else
		return kmem_cache_alloc(pgd_cache, gfp);
}

void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	if (PGD_SIZE == PAGE_SIZE)
		free_page((unsigned long)pgd);
	else
		kmem_cache_free(pgd_cache, pgd);
}

void __init pgtable_cache_init(void)
{
	if (PGD_SIZE == PAGE_SIZE)
		return;

#ifdef CONFIG_ARM64_PA_BITS_52
	/*
	 * With 52-bit physical addresses, the architecture requires the
	 * top-level table to be aligned to at least 64 bytes.
	 */
	BUILD_BUG_ON(PGD_SIZE < 64);
#endif

	/*
	 * Naturally aligned pgds required by the architecture.
	 */
	pgd_cache = kmem_cache_create("pgd_cache", PGD_SIZE, PGD_SIZE,
				      SLAB_PANIC, NULL);
}

pte_t xchg_ro_pte(struct mm_struct *mm, pte_t *ptep, pte_t pte)
{
	unsigned long flags;
	pte_t ret;
	pte_t *p;

	if (!virt_addr_valid(ptep)) {
		/* only linear aliases are remapped r/o */
		pte_val(ret) = xchg_relaxed(&pte_val(*ptep), pte_val(pte));
		return pte;
	}

	raw_spin_lock_irqsave(&patch_pte_lock, flags);
	p = (pte_t *)set_fixmap_offset(FIX_TEXT_POKE_PTE, __pa(ptep));
	pte_val(ret) = xchg_relaxed(&pte_val(*p), pte_val(pte));
	clear_fixmap(FIX_TEXT_POKE_PTE);
	raw_spin_unlock_irqrestore(&patch_pte_lock, flags);
	return ret;
}

pte_t cmpxchg_ro_pte(struct mm_struct *mm, pte_t *ptep, pte_t old, pte_t new)
{
	unsigned long flags;
	pte_t ret;
	pte_t *p;

	VM_BUG_ON(!virt_addr_valid(ptep));

	raw_spin_lock_irqsave(&patch_pte_lock, flags);
	p = (pte_t *)set_fixmap_offset(FIX_TEXT_POKE_PTE, __pa(ptep));
	pte_val(ret) = cmpxchg_relaxed(&pte_val(*p), pte_val(old), pte_val(new));
	clear_fixmap(FIX_TEXT_POKE_PTE);
	raw_spin_unlock_irqrestore(&patch_pte_lock, flags);
	return ret;
}
