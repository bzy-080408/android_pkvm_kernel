// SPDX-License-Identifier: GPL-2.0-only
#ifndef __KVM_HYP_MAPPINGS
#define __KVM_HYP_MAPPINGS

#ifndef hyp_get_page
#define hyp_get_page get_page
#endif

#ifndef hyp_put_page
#define hyp_put_page put_page
#endif

#ifndef hyp_virt_to_page
#define hyp_virt_to_page virt_to_page
#endif

static inline void kvm_set_pte(pte_t *ptep, pte_t new_pte)
{
	WRITE_ONCE(*ptep, new_pte);
	dsb(ishst);
}

static inline void kvm_set_pmd(pmd_t *pmdp, pmd_t new_pmd)
{
	WRITE_ONCE(*pmdp, new_pmd);
	dsb(ishst);
}

static inline void kvm_pmd_populate(pmd_t *pmdp, pte_t *ptep)
{
	kvm_set_pmd(pmdp, kvm_mk_pmd(ptep));
}

static inline void kvm_pud_populate(pud_t *pudp, pmd_t *pmdp)
{
	WRITE_ONCE(*pudp, kvm_mk_pud(pmdp));
	dsb(ishst);
}

static inline void kvm_p4d_populate(p4d_t *p4dp, pud_t *pudp)
{
	WRITE_ONCE(*p4dp, kvm_mk_p4d(pudp));
	dsb(ishst);
}

static inline void kvm_pgd_populate(pgd_t *pgdp, p4d_t *p4dp)
{
#ifndef __PAGETABLE_P4D_FOLDED
	WRITE_ONCE(*pgdp, kvm_mk_pgd(p4dp));
	dsb(ishst);
#endif
}

static inline void clear_hyp_pgd_entry(pgd_t *pgd)
{
	p4d_t *p4d_table __maybe_unused = p4d_offset(pgd, 0UL);
	pgd_clear(pgd);
	p4d_free(NULL, p4d_table);
	hyp_put_page(hyp_virt_to_page(pgd));
}

static inline void clear_hyp_p4d_entry(p4d_t *p4d)
{
	pud_t *pud_table __maybe_unused = pud_offset(p4d, 0UL);
	VM_BUG_ON(p4d_huge(*p4d));
	p4d_clear(p4d);
	pud_free(NULL, pud_table);
	hyp_put_page(hyp_virt_to_page(p4d));
}

static inline void clear_hyp_pud_entry(pud_t *pud)
{
	pmd_t *pmd_table __maybe_unused = pmd_offset(pud, 0);
	VM_BUG_ON(pud_huge(*pud));
	pud_clear(pud);
	pmd_free(NULL, pmd_table);
	hyp_put_page(hyp_virt_to_page(pud));
}

static inline void clear_hyp_pmd_entry(pmd_t *pmd)
{
	pte_t *pte_table = pte_offset_kernel(pmd, 0);
	VM_BUG_ON(pmd_thp_or_huge(*pmd));
	pmd_clear(pmd);
	pte_free_kernel(NULL, pte_table);
	hyp_put_page(hyp_virt_to_page(pmd));
}

static inline void unmap_hyp_ptes(pmd_t *pmd, phys_addr_t addr, phys_addr_t end)
{
	pte_t *pte, *start_pte;

	start_pte = pte = pte_offset_kernel(pmd, addr);
	do {
		if (!pte_none(*pte)) {
			kvm_set_pte(pte, __pte(0));
			hyp_put_page(hyp_virt_to_page(pte));
		}
	} while (pte++, addr += PAGE_SIZE, addr != end);

	if (hyp_pte_table_empty(start_pte))
		clear_hyp_pmd_entry(pmd);
}

static inline void unmap_hyp_pmds(pud_t *pud, phys_addr_t addr, phys_addr_t end)
{
	phys_addr_t next;
	pmd_t *pmd, *start_pmd;

	start_pmd = pmd = pmd_offset(pud, addr);
	do {
		next = pmd_addr_end(addr, end);
		/* Hyp doesn't use huge pmds */
		if (!pmd_none(*pmd))
			unmap_hyp_ptes(pmd, addr, next);
	} while (pmd++, addr = next, addr != end);

	if (hyp_pmd_table_empty(start_pmd))
		clear_hyp_pud_entry(pud);
}

static inline void unmap_hyp_puds(p4d_t *p4d, phys_addr_t addr, phys_addr_t end)
{
	phys_addr_t next;
	pud_t *pud, *start_pud;

	start_pud = pud = pud_offset(p4d, addr);
	do {
		next = pud_addr_end(addr, end);
		/* Hyp doesn't use huge puds */
		if (!pud_none(*pud))
			unmap_hyp_pmds(pud, addr, next);
	} while (pud++, addr = next, addr != end);

	if (hyp_pud_table_empty(start_pud))
		clear_hyp_p4d_entry(p4d);
}

static inline void unmap_hyp_p4ds(pgd_t *pgd, phys_addr_t addr, phys_addr_t end)
{
	phys_addr_t next;
	p4d_t *p4d, *start_p4d;

	start_p4d = p4d = p4d_offset(pgd, addr);
	do {
		next = p4d_addr_end(addr, end);
		/* Hyp doesn't use huge p4ds */
		if (!p4d_none(*p4d))
			unmap_hyp_puds(p4d, addr, next);
	} while (p4d++, addr = next, addr != end);

	if (hyp_p4d_table_empty(start_p4d))
		clear_hyp_pgd_entry(pgd);
}

static inline unsigned int kvm_pgd_index(unsigned long addr, unsigned int ptrs_per_pgd)
{
	return (addr >> PGDIR_SHIFT) & (ptrs_per_pgd - 1);
}

static inline void __unmap_hyp_range(pgd_t *pgdp, unsigned long ptrs_per_pgd,
				     phys_addr_t start, u64 size)
{
	pgd_t *pgd;
	phys_addr_t addr = start, end = start + size;
	phys_addr_t next;

	/*
	 * We don't unmap anything from HYP, except at the hyp tear down.
	 * Hence, we don't have to invalidate the TLBs here.
	 */
	pgd = pgdp + kvm_pgd_index(addr, ptrs_per_pgd);
	do {
		next = pgd_addr_end(addr, end);
		if (!pgd_none(*pgd))
			unmap_hyp_p4ds(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
}

static inline void create_hyp_pte_mappings(pmd_t *pmd, unsigned long start,
					   unsigned long end, unsigned long pfn,
					   pgprot_t prot)
{
	pte_t *pte;
	unsigned long addr;

	addr = start;
	do {
		pte = pte_offset_kernel(pmd, addr);
		kvm_set_pte(pte, kvm_pfn_pte(pfn, prot));
		hyp_get_page(hyp_virt_to_page(pte));
		pfn++;
	} while (addr += PAGE_SIZE, addr != end);
}

static inline int create_hyp_pmd_mappings(pud_t *pud, unsigned long start,
					  unsigned long end, unsigned long pfn,
					  pgprot_t prot)
{
	pmd_t *pmd;
	pte_t *pte;
	unsigned long addr, next;

	addr = start;
	do {
		pmd = pmd_offset(pud, addr);

		BUG_ON(pmd_sect(*pmd));

		if (pmd_none(*pmd)) {
			pte = pte_alloc_one_kernel(NULL);
			if (!pte) {
				kvm_err("Cannot allocate Hyp pte\n");
				return -ENOMEM;
			}
			kvm_pmd_populate(pmd, pte);
			hyp_get_page(hyp_virt_to_page(pmd));
		}

		next = pmd_addr_end(addr, end);

		create_hyp_pte_mappings(pmd, addr, next, pfn, prot);
		pfn += (next - addr) >> PAGE_SHIFT;
	} while (addr = next, addr != end);

	return 0;
}

static inline int create_hyp_pud_mappings(p4d_t *p4d, unsigned long start,
					  unsigned long end, unsigned long pfn,
					  pgprot_t prot)
{
	pud_t *pud;
	pmd_t *pmd;
	unsigned long addr, next;
	int ret;

	addr = start;
	do {
		pud = pud_offset(p4d, addr);

		if (pud_none_or_clear_bad(pud)) {
			pmd = pmd_alloc_one(NULL, addr);
			if (!pmd) {
				kvm_err("Cannot allocate Hyp pmd\n");
				return -ENOMEM;
			}
			kvm_pud_populate(pud, pmd);
			hyp_get_page(hyp_virt_to_page(pud));
		}

		next = pud_addr_end(addr, end);
		ret = create_hyp_pmd_mappings(pud, addr, next, pfn, prot);
		if (ret)
			return ret;
		pfn += (next - addr) >> PAGE_SHIFT;
	} while (addr = next, addr != end);

	return 0;
}

static inline int create_hyp_p4d_mappings(pgd_t *pgd, unsigned long start,
					  unsigned long end, unsigned long pfn,
					  pgprot_t prot)
{
	p4d_t *p4d;
	pud_t *pud;
	unsigned long addr, next;
	int ret;

	addr = start;
	do {
		p4d = p4d_offset(pgd, addr);

		if (p4d_none(*p4d)) {
			pud = pud_alloc_one(NULL, addr);
			if (!pud) {
				kvm_err("Cannot allocate Hyp pud\n");
				return -ENOMEM;
			}
			kvm_p4d_populate(p4d, pud);
			hyp_get_page(hyp_virt_to_page(p4d));
		}

		next = p4d_addr_end(addr, end);
		ret = create_hyp_pud_mappings(p4d, addr, next, pfn, prot);
		if (ret)
			return ret;
		pfn += (next - addr) >> PAGE_SHIFT;
	} while (addr = next, addr != end);

	return 0;
}

static inline int __create_hyp_mappings_locked(pgd_t *pgdp,
					       unsigned long ptrs_per_pgd,
					       unsigned long start,
					       unsigned long end,
					       unsigned long pfn,
					       pgprot_t prot)
{
	pgd_t *pgd;
	p4d_t *p4d;
	unsigned long addr, next;
	int err = 0;

	addr = start & PAGE_MASK;
	end = PAGE_ALIGN(end);
	do {
		pgd = pgdp + kvm_pgd_index(addr, ptrs_per_pgd);

		if (pgd_none(*pgd)) {
			p4d = p4d_alloc_one(NULL, addr);
			if (!p4d) {
				kvm_err("Cannot allocate Hyp p4d\n");
				err = -ENOMEM;
				goto out;
			}
			kvm_pgd_populate(pgd, p4d);
			hyp_get_page(hyp_virt_to_page(pgd));
		}

		next = pgd_addr_end(addr, end);
		err = create_hyp_p4d_mappings(pgd, addr, next, pfn, prot);
		if (err)
			goto out;
		pfn += (next - addr) >> PAGE_SHIFT;
	} while (addr = next, addr != end);
out:
	return err;
}

#endif /* __KVM_HYP_MAPPINGS */
