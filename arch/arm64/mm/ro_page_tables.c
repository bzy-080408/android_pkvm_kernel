// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google Inc
 * Author: Ard Biesheuvel <ardb@google.com>
 */

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/memory.h>
#include <linux/mm.h>
#include <linux/sizes.h>

#include <asm/fixmap.h>
#include <asm/kernel-pgtable.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/tlbflush.h>
#include <asm/sections.h>

static DEFINE_RAW_SPINLOCK(patch_pte_lock);

DEFINE_STATIC_KEY_FALSE(ro_page_tables);

static bool __initdata ro_page_tables_enabled = true;

static int __init parse_ro_page_tables(char *arg)
{
	return strtobool(arg, &ro_page_tables_enabled);
}
early_param("ro_page_tables", parse_ro_page_tables);

static bool in_kernel_text_or_rodata(phys_addr_t pa)
{
	/*
	 * This is a minimal check to ensure that the r/o page table patching
	 * API is not being abused to make changes to the kernel text. This
	 * should ideally cover module and BPF text/rodata as well, but that
	 * is less straight-forward and hence more costly.
	 */
	return pa >= __pa_symbol(_stext) && pa < __pa_symbol(__init_begin);
}

pte_t xchg_ro_pte(struct mm_struct *mm, pte_t *ptep, pte_t pte)
{
	unsigned long flags;
	u64 pte_pa;
	pte_t ret;
	pte_t *p;

	/* can we use __pa() on ptep? */
	if (!virt_addr_valid(ptep)) {
		/* only linear aliases are remapped r/o anyway */
		pte_val(ret) = xchg_relaxed(&pte_val(*ptep), pte_val(pte));
		return ret;
	}

	pte_pa = __pa(ptep);
	BUG_ON(in_kernel_text_or_rodata(pte_pa));

	raw_spin_lock_irqsave(&patch_pte_lock, flags);
	p = (pte_t *)set_fixmap_offset(FIX_TEXT_POKE_PTE, pte_pa);
	pte_val(ret) = xchg_relaxed(&pte_val(*p), pte_val(pte));
	clear_fixmap(FIX_TEXT_POKE_PTE);
	raw_spin_unlock_irqrestore(&patch_pte_lock, flags);
	return ret;
}

pte_t cmpxchg_ro_pte(struct mm_struct *mm, pte_t *ptep, pte_t old, pte_t new)
{
	unsigned long flags;
	u64 pte_pa;
	pte_t ret;
	pte_t *p;

	BUG_ON(!virt_addr_valid(ptep));

	pte_pa = __pa(ptep);
	BUG_ON(in_kernel_text_or_rodata(pte_pa));

	raw_spin_lock_irqsave(&patch_pte_lock, flags);
	p = (pte_t *)set_fixmap_offset(FIX_TEXT_POKE_PTE, pte_pa);
	pte_val(ret) = cmpxchg_relaxed(&pte_val(*p), pte_val(old), pte_val(new));
	clear_fixmap(FIX_TEXT_POKE_PTE);
	raw_spin_unlock_irqrestore(&patch_pte_lock, flags);
	return ret;
}

static int __init ro_page_tables_init(void)
{
	if (ro_page_tables_enabled) {
		if (!rodata_full) {
			pr_err("Failed to enable R/O page table protection, rodata=full is not enabled\n");
		} else {
			pr_err("Enabling R/O page table protection\n");
			static_branch_enable(&ro_page_tables);
		}
	}
	return 0;
}
early_initcall(ro_page_tables_init);
