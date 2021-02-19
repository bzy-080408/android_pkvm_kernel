/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/pgalloc.h
 *
 * Copyright (C) 2000-2001 Russell King
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_PGALLOC_H
#define __ASM_PGALLOC_H

#include <asm/pgtable-hwdef.h>
#include <asm/processor.h>
#include <asm/cacheflush.h>
#include <asm/tlbflush.h>

#define __HAVE_ARCH_PGD_FREE
#define __HAVE_ARCH_PUD_ALLOC_ONE
#define __HAVE_ARCH_PUD_FREE
#define __HAVE_ARCH_PMD_ALLOC_ONE
#define __HAVE_ARCH_PMD_FREE
#define __HAVE_ARCH_PTE_ALLOC_ONE
#define __HAVE_ARCH_PTE_FREE
#include <asm-generic/pgalloc.h>

#define PGD_SIZE	(PTRS_PER_PGD * sizeof(pgd_t))

pgtable_t pte_alloc_one(struct mm_struct *mm);
void pte_free(struct mm_struct *mm, struct page *pte_page);

#if CONFIG_PGTABLE_LEVELS > 2

pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr);
void pmd_free(struct mm_struct *mm, pmd_t *pmd);

static inline void __pud_populate(pud_t *pudp, phys_addr_t pmdp, pudval_t prot)
{
	set_pud(pudp, __pud(__phys_to_pud_val(pmdp) | prot));
}

static inline void pud_populate(struct mm_struct *mm, pud_t *pudp, pmd_t *pmdp)
{
	pudval_t pudval = PUD_TYPE_TABLE;

	pudval |= (mm == &init_mm) ? PUD_TABLE_UXN : PUD_TABLE_PXN;
	if (page_tables_are_ro())
		xchg_ro_pte(mm, (pte_t *)pudp,
			    __pte(__phys_to_pud_val(__pa(pmdp) | pudval)));
	else
		__pud_populate(pudp, __pa(pmdp), pudval);
}
#else
static inline void __pud_populate(pud_t *pudp, phys_addr_t pmdp, pudval_t prot)
{
	BUILD_BUG();
}
#endif	/* CONFIG_PGTABLE_LEVELS > 2 */

#if CONFIG_PGTABLE_LEVELS > 3

pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr);
void pud_free(struct mm_struct *mm, pud_t *pud);

static inline void __p4d_populate(p4d_t *p4dp, phys_addr_t pudp, p4dval_t prot)
{
	set_p4d(p4dp, __p4d(__phys_to_p4d_val(pudp) | prot));
}

static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4dp, pud_t *pudp)
{
	p4dval_t p4dval = P4D_TYPE_TABLE;

	p4dval |= (mm == &init_mm) ? P4D_TABLE_UXN : P4D_TABLE_PXN;
	if (page_tables_are_ro())
		xchg_ro_pte(mm, (pte_t *)p4dp,
			    __pte(__phys_to_p4d_val(__pa(pudp) | p4dval)));
	else
		__p4d_populate(p4dp, __pa(pudp), p4dval);
}
#else
static inline void __p4d_populate(p4d_t *p4dp, phys_addr_t pudp, p4dval_t prot)
{
	BUILD_BUG();
}
#endif	/* CONFIG_PGTABLE_LEVELS > 3 */

extern pgd_t *pgd_alloc(struct mm_struct *mm);
extern void pgd_free(struct mm_struct *mm, pgd_t *pgdp);

static inline void __pmd_populate(pmd_t *pmdp, phys_addr_t ptep,
				  pmdval_t prot)
{
	set_pmd(pmdp, __pmd(__phys_to_pmd_val(ptep) | prot));
}

/*
 * Populate the pmdp entry with a pointer to the pte.  This pmd is part
 * of the mm address space.
 */
static inline void
pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmdp, pte_t *ptep)
{
	pmdval_t pmdval = PMD_TYPE_TABLE | PMD_TABLE_UXN;

	VM_BUG_ON(mm != &init_mm);
	if (page_tables_are_ro())
		xchg_ro_pte(mm, (pte_t *)pmdp,
			    __pte(__phys_to_pmd_val(__pa(ptep) | pmdval)));
	else
		__pmd_populate(pmdp, __pa(ptep), pmdval);
}

static inline void
pmd_populate(struct mm_struct *mm, pmd_t *pmdp, pgtable_t ptep)
{
	pmdval_t pmdval = PMD_TYPE_TABLE | PMD_TABLE_PXN;

	VM_BUG_ON(mm == &init_mm);
	if (page_tables_are_ro())
		xchg_ro_pte(mm, (pte_t *)pmdp,
			    __pte(__phys_to_pmd_val(page_to_phys(ptep) | pmdval)));
	else
		__pmd_populate(pmdp, page_to_phys(ptep), pmdval);
}
#define pmd_pgtable(pmd) pmd_page(pmd)

#endif
