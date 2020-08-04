/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_HYP_MMU_H
#define __KVM_HYP_MMU_H

#define kvm_pfn_pte(pfn, prot)		pfn_pte(pfn, prot)
#define kvm_pfn_pmd(pfn, prot)		pfn_pmd(pfn, prot)
#define kvm_pfn_pud(pfn, prot)		pfn_pud(pfn, prot)

#define kvm_mk_pmd(ptep) __pmd(__phys_to_pmd_val(__hyp_pa(ptep)) | PMD_TYPE_TABLE)
#define kvm_mk_pud(pmdp) __pud(__phys_to_pud_val(__hyp_pa(pmdp)) | PMD_TYPE_TABLE)
#define kvm_mk_p4d(pmdp) __p4d(__phys_to_p4d_val(__hyp_pa(pmdp)) | PUD_TYPE_TABLE)

#define kvm_page_empty(virt)	(hyp_page_count(hyp_virt_to_page(virt)) == 1)

#define hyp_pte_table_empty(ptep) kvm_page_empty(ptep)

#ifdef __PAGETABLE_PMD_FOLDED
#define hyp_pmd_table_empty(pmdp) (0)
#else
#define hyp_pmd_table_empty(pmdp) kvm_page_empty(pmdp)
#endif

#ifdef __PAGETABLE_PUD_FOLDED
#define hyp_pud_table_empty(pudp) (0)
#else
#define hyp_pud_table_empty(pudp) kvm_page_empty(pudp)
#endif

#ifdef __PAGETABLE_P4D_FOLDED
#define hyp_p4d_table_empty(p4dp) (0)
#else
#define hyp_p4d_table_empty(p4dp) kvm_page_empty(p4dp)
#endif

static inline void pud_free(void *mm, pud_t *pudp)
{
	hyp_free_page((unsigned long)pudp);
}
static inline void pmd_free(void *mm, pmd_t *pmdp)
{
	hyp_free_page((unsigned long)pmdp);
}
static inline void pte_free_kernel(void *mm, pte_t *ptep)
{
	hyp_free_page((unsigned long)ptep);
}

static inline pte_t *pte_alloc_one_kernel(void *mm)
{
	return (pte_t *)hyp_host_get_zeroed_pages(0);
}

static inline pmd_t *pmd_alloc_one(void *mm, unsigned long addr)
{
	return (pmd_t *)hyp_host_get_zeroed_pages(0);
}

static inline pud_t *pud_alloc_one(void *mm, unsigned long addr)
{
	return (pud_t *)hyp_host_get_zeroed_pages(0);
}

#endif /* __KVM_HYP_MMU_H */
