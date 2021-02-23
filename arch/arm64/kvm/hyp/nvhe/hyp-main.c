// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <hyp/switch.h>

#include <asm/pgtable-types.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_host.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/trap_handler.h>

DEFINE_PER_CPU(struct kvm_nvhe_init_params, kvm_init_params);

void __kvm_hyp_host_forward_smc(struct kvm_cpu_context *host_ctxt);

static void handle___kvm_vcpu_run(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_vcpu *, vcpu, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) =  __kvm_vcpu_run(kern_hyp_va(vcpu));
}

static void handle___kvm_flush_vm_context(struct kvm_cpu_context *host_ctxt)
{
	__kvm_flush_vm_context();
}

static void handle___kvm_tlb_flush_vmid_ipa(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);
	DECLARE_REG(phys_addr_t, ipa, host_ctxt, 2);
	DECLARE_REG(int, level, host_ctxt, 3);

	__kvm_tlb_flush_vmid_ipa(kern_hyp_va(mmu), ipa, level);
}

static void handle___kvm_tlb_flush_vmid(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);

	__kvm_tlb_flush_vmid(kern_hyp_va(mmu));
}

static void handle___kvm_flush_cpu_context(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct kvm_s2_mmu *, mmu, host_ctxt, 1);

	__kvm_flush_cpu_context(kern_hyp_va(mmu));
}

static void handle___kvm_timer_set_cntvoff(struct kvm_cpu_context *host_ctxt)
{
	__kvm_timer_set_cntvoff(cpu_reg(host_ctxt, 1));
}

static void handle___kvm_enable_ssbs(struct kvm_cpu_context *host_ctxt)
{
	u64 tmp;

	tmp = read_sysreg_el2(SYS_SCTLR);
	tmp |= SCTLR_ELx_DSSBS;
	write_sysreg_el2(tmp, SYS_SCTLR);
}

static void handle___vgic_v3_get_gic_config(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __vgic_v3_get_gic_config();
}

static void handle___vgic_v3_read_vmcr(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __vgic_v3_read_vmcr();
}

static void handle___vgic_v3_write_vmcr(struct kvm_cpu_context *host_ctxt)
{
	__vgic_v3_write_vmcr(cpu_reg(host_ctxt, 1));
}

static void handle___vgic_v3_init_lrs(struct kvm_cpu_context *host_ctxt)
{
	__vgic_v3_init_lrs();
}

static void handle___kvm_get_mdcr_el2(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __kvm_get_mdcr_el2();
}

static void handle___vgic_v3_save_aprs(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct vgic_v3_cpu_if *, cpu_if, host_ctxt, 1);

	__vgic_v3_save_aprs(kern_hyp_va(cpu_if));
}

static void handle___vgic_v3_restore_aprs(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(struct vgic_v3_cpu_if *, cpu_if, host_ctxt, 1);

	__vgic_v3_restore_aprs(kern_hyp_va(cpu_if));
}

static void handle___pkvm_init(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(phys_addr_t, phys, host_ctxt, 1);
	DECLARE_REG(unsigned long, size, host_ctxt, 2);
	DECLARE_REG(unsigned long, nr_cpus, host_ctxt, 3);
	DECLARE_REG(unsigned long *, per_cpu_base, host_ctxt, 4);
	DECLARE_REG(u32, hyp_va_bits, host_ctxt, 5);

	/*
	 * __pkvm_init() will return only if an error occurred, otherwise it
	 * will tail-call in __pkvm_init_finalise() which will have to deal
	 * with the host context directly.
	 */
	cpu_reg(host_ctxt, 1) = __pkvm_init(phys, size, nr_cpus, per_cpu_base,
					    hyp_va_bits);
}

static void handle___pkvm_cpu_set_vector(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(enum arm64_hyp_spectre_vector, slot, host_ctxt, 1);

	cpu_reg(host_ctxt, 1) = pkvm_cpu_set_vector(slot);
}

static void handle___pkvm_create_mappings(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(unsigned long, start, host_ctxt, 1);
	DECLARE_REG(unsigned long, size, host_ctxt, 2);
	DECLARE_REG(unsigned long, phys, host_ctxt, 3);
	DECLARE_REG(enum kvm_pgtable_prot, prot, host_ctxt, 4);

	cpu_reg(host_ctxt, 1) = __pkvm_create_mappings(start, size, phys, prot);
}

static void handle___pkvm_create_private_mapping(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(phys_addr_t, phys, host_ctxt, 1);
	DECLARE_REG(size_t, size, host_ctxt, 2);
	DECLARE_REG(enum kvm_pgtable_prot, prot, host_ctxt, 3);

	cpu_reg(host_ctxt, 1) = __pkvm_create_private_mapping(phys, size, prot);
}

static void handle___pkvm_prot_finalize(struct kvm_cpu_context *host_ctxt)
{
	cpu_reg(host_ctxt, 1) = __pkvm_prot_finalize();
}

static void handle___pkvm_mark_hyp(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(phys_addr_t, start, host_ctxt, 1);
	DECLARE_REG(phys_addr_t, end, host_ctxt, 2);

	cpu_reg(host_ctxt, 1) = __pkvm_mark_hyp(start, end);
}

static void inject_external_abort(struct kvm_cpu_context *host_ctxt)
{
	struct kvm_vcpu *vcpu = host_ctxt->__hyp_running_vcpu;

	if (vcpu)
		; // TODO

	write_sysreg_el2(read_sysreg_el2(SYS_ELR) - 1, SYS_ELR);
}

/*
 * Resolve @address against the page table hierarchy starting from @pgd, and
 * decide whether @pteval appearing at @ptep amounts to a block or page mapping
 * for @address. In doubt, return false.
 */
static bool is_block_or_page_mapping(pgd_t *pgd, u64 addr, pte_t *ptep,
				     u64 pteval, int *level)
{
	bool is_block = false;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	*level = -1;

	/* not enough information to decide - err on the side of caution */
	if (!pgd || addr == ULONG_MAX)
		return false;

	/* check for block mapping - encodings are the same for levels < 3 */
	if ((pteval & PMD_TYPE_MASK) == PMD_TYPE_SECT)
		is_block = true;

	/*
	 * pteval is a valid entry, and could describe either a table mapping
	 * or a page mapping, depending on which level it happens to appear at.
	 * Walk the page tables to figure this out.
	 */
	if (!(((u64)pgd ^ (u64)ptep) & PAGE_MASK)) {
		*level = 4 - CONFIG_PGTABLE_LEVELS;
		return (*level > 0) ? is_block : false;
	}

	p4d = (p4d_t *)__pgd_to_phys(kern_hyp_va(pgd)[pgd_index(addr)]);
	if (__is_defined(__PAGETABLE_P4D_FOLDED)) {
		pud = (pud_t *)p4d;
	} else {
		if (!(((u64)p4d ^ (u64)ptep) & PAGE_MASK)) {
			*level = 0;
			return false;
		}
		pud = (pud_t *)__p4d_to_phys(kern_hyp_va(p4d)[p4d_index(addr)]);
	}

	if (__is_defined(__PAGETABLE_PUD_FOLDED)) {
		pmd = (pmd_t *)pud;
	} else {
		if (!(((u64)pud ^ (u64)ptep) & PAGE_MASK)) {
			*level = 1;
			return is_block;
		}
		pmd = (pmd_t *)__pud_to_phys(kern_hyp_va(pud)[pud_index(addr)]);
	}

	if (__is_defined(__PAGETABLE_PMD_FOLDED)) {
		pte = (pte_t *)pmd;
	} else {
		if (!(((u64)pmd ^ (u64)ptep) & PAGE_MASK)) {
			*level = 2;
			return is_block;
		}
		pte = (pte_t *)__pmd_to_phys(kern_hyp_va(pmd)[pmd_index(addr)]);
	}

	if (!(((u64)pte ^ (u64)ptep) & PAGE_MASK)) {
		*level = 3;
		return true;
	}

	return false;
}

/*
 * Check whether creating @count valid entries at @level for the target pages
 * described in @pteval[] is permitted by the policy.
 */
static bool pkvm_pgtable_policy_allows(const pgd_t *pgd, bool is_table,
				       int level, const u64 *pteval, int count)
{
	int i;

	if (level == 3) {
		/*
		 * Don't allow page mappings of pgtable pages, to avoid
		 * mistaking them for table mappings upon release.
		 */
		for (i = 0; i < count; i++) {
			u64 pa = __pte_to_phys(__pte(pteval[i]));

			if ((pteval[i] & PTE_VALID) &&
			    kvm_pgtable_stage2_is_pg(&host_kvm.pgt, pa))
				return false;
		}
	}

	//
	//
	// TODO invoke policy engine
	//
	//

	return true;
}

/*
 * Life cycle of a EL1 page table
 * ==============================
 *
 * EL1 is in charge of allocating and freeing pages to be used for intermediate
 * page tables, but we have to keep track of them at EL2 in order to maintain
 * read-only mappings of those pages at stage 2, to force the EL1 OS to use the
 * HYP api to make modifications to the layout of each virtual address space.
 *
 * While root page tables are assigned and released explicitly, intermediate
 * page tables are tracked by interpreting the changes made by the EL1 OS using
 * the routine below. If the call results in a table entry to be created or
 * removed, this fact must be reflected in the stage 2 tracking of the page.
 *
 * So the simple rules are:
 * - if the update creates a table mapping, the target page is remapped
 *   read-only at stage 2, wiped (*) and marked as a table page, unless it
 *   is already in that state, in which case the update is rejected;
 * - if the update removes a table mapping, the target page is released and
 *   marked read-write again.
 *
 * There are two issues that make this slightly more complicated than desired:
 * - The core mm layer in Linux does not provide a target address for every page
 *   table modification arriving through the API below, but only for ones that
 *   create block or page mappings.
 * - we cannot easily distinguish between level 3 page mappings and higher level
 *   table mappings, given that they use the same descriptor bit.
 *
 * A new valid mapping is assumed to be a table mapping unless the pgd+address
 * arguments identify it positively as a block or page mapping. The target of a
 * new table mapping must not be in pgroot or pgtable state, and will be wiped
 * and moved into pgtable state before the new valid mapping is created.
 *
 * If the new descriptor value is 0x0 and the entry is covered by a pgroot or
 * pgtable page, and refers to a page that is currently in pgtable state, the
 * page is reverted to default state after the old valid mapping is removed.
 *
 * (*) migration of level 2 entries is permitted as well, but only if all valid
 *     level 3 mappings they cover comply with the policy.
 */
static void handle___pkvm_xchg_ro_pte(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(pgd_t *, pgdp, host_ctxt, 1);
	DECLARE_REG(u64, address, host_ctxt, 2);
	DECLARE_REG(pte_t *, ptep, host_ctxt, 3);
	DECLARE_REG(u64, pteval, host_ctxt, 4);
	bool is_pgtable;
	u64 oldval;

	is_pgtable = kvm_pgtable_stage2_is_pg(&host_kvm.pgt, (u64)ptep);

	if (is_pgtable && (pteval & PTE_VALID)) {
		bool is_table;
		int level;

		/* valid entries must be created in the context of a pgd[] */
		if (!pgdp) {
			// TODO check whether pgdp is pgroot??
			inject_external_abort(host_ctxt);
			return;
		}

		is_table = !is_block_or_page_mapping(pgdp, address, ptep,
						     pteval, &level);

		if (!pkvm_pgtable_policy_allows(pgdp, is_table, level, &pteval, 1)) {
			inject_external_abort(host_ctxt);
			return;
		}

		if (is_table) {
			u64 pa = __pte_to_phys(__pte(pteval));

			// TODO this needs to have cmpxchg semantics to avoid races
			if (!kvm_pgtable_stage2_make_pgtable(&host_kvm.pgt, pa)) {
				inject_external_abort(host_ctxt);
				return;
			}

			// map the page table at hyp so we can manipulate it
			__pkvm_create_mappings(kern_hyp_va(pa), PAGE_SIZE, pa,
					       PAGE_HYP);

			if (level == 2) {
				// We permit moving level 2 entries as long
				// as all valid level 3 entry they carry pass
				// the policy check
				if (!pkvm_pgtable_policy_allows(pgdp, false, 3,
								(u64 *)kern_hyp_va(pa),
								PTRS_PER_PTE)) {
					inject_external_abort(host_ctxt);
					return;
				}
			} else {
				// wipe the page before first use
				memset((void *)kern_hyp_va(pa), 0, PAGE_SIZE);
			}
		}
	}

	if (!is_pgtable) {
		u64 ptaddr = (u64)kern_hyp_va(ptep) & PAGE_MASK;

		/*
		 * If ptep points into a page that we are not tracking, it may
		 * not be mapped at stage 2 yet.
		 */
		__pkvm_create_mappings(ptaddr, PAGE_SIZE, (u64)ptep & PAGE_MASK,
				       PAGE_HYP);
	}

	oldval = xchg_relaxed(&pte_val(*kern_hyp_va(ptep)), pteval);

	/*
	 * If the old entry was a valid table or page entry, assume it is the
	 * former and stop tracking it as a page table.
	 */
	if (is_pgtable && (oldval & PTE_TYPE_MASK) == PTE_TYPE_PAGE) {
		/*
		 * If we are removing a mapping from a pgtable/pgroot page and
		 * the entry targets a pgtable page, move it to default state.
		 */
		kvm_pgtable_stage2_clear_pgtable(&host_kvm.pgt,
						 __pte_to_phys(__pte(oldval)));
	}
	cpu_reg(host_ctxt, 1) = oldval;
}

static void handle___pkvm_cmpxchg_ro_pte(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(pte_t *, ptep, host_ctxt, 1);
	DECLARE_REG(u64, oldval, host_ctxt, 2);
	DECLARE_REG(u64, newval, host_ctxt, 3);

	/*
	 * cmpxchg_ro_pte() must only be used when updates to mapping attributes
	 * performed by the CPU may race with updates of the access/dirty flags
	 * by the page table walker. If we can enforce this at HYP level, there
	 * is no need to go through the policy check at all.
	 */
	if (((oldval ^ newval) & ~(PTE_DIRTY|PTE_WRITE|PTE_AF|PTE_RDONLY)) ||
	    !kvm_pgtable_stage2_is_pg(&host_kvm.pgt, (u64)ptep)) {
		inject_external_abort(host_ctxt);
		return;
	}

	cpu_reg(host_ctxt, 1) = cmpxchg_relaxed(&pte_val(*kern_hyp_va(ptep)),
						oldval, newval);
}

static void handle___pkvm_assign_pgroot(struct kvm_cpu_context *host_ctxt)
{
	/*
	 * We don't permit the root table's address to be used in TTBRn_EL1 by
	 * the host unless the page is mapped read-only at stage2, and carries
	 * the correct annotation (rt@s2). If the page is not in the correct
	 * state yet, set the correct state and wipe the contents. This ensures
	 * that a root page table only contains entries that were vetted by the
	 * HYP api.
	 */
	DECLARE_REG(pgd_t *, pgdp, host_ctxt, 1);
	u64 ptaddr = (u64)kern_hyp_va(pgdp) & PAGE_MASK;

	// remap the page as r/o at stage, and tag as a pgd[]
	if (!kvm_pgtable_stage2_make_pgroot(&host_kvm.pgt, (u64)pgdp)) {
		inject_external_abort(host_ctxt);
		return;
	}

	// create stage1@el2 mapping if needed
	__pkvm_create_mappings(ptaddr, PAGE_SIZE, (u64)pgdp & PAGE_MASK, PAGE_HYP);

	// wipe the page before first use
	memset((void *)ptaddr, 0, PAGE_SIZE);
}

extern unsigned long hyp_nr_cpus;

static void handle___pkvm_release_pgroot(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(pgd_t *, pgdp, host_ctxt, 1);
	u64 ptaddr = (u64)kern_hyp_va(pgdp) & PAGE_MASK;
	int i;

	/* check that the root pgtable is not live on any CPU */
	for (i = 0; i < hyp_nr_cpus; i++) {
		const struct kvm_cpu_context *ctx;

		ctx = &per_cpu_ptr(&kvm_host_data, i)->host_ctxt;
		if ((ctx->sys_regs[TTBR0_EL1] & ~TTBR_ASID_MASK) == ptaddr) {
			inject_external_abort(host_ctxt);
			return;
		}
	}

	if (!kvm_pgtable_stage2_clear_pgroot(&host_kvm.pgt, (u64)pgdp))
		inject_external_abort(host_ctxt);
}

typedef void (*hcall_t)(struct kvm_cpu_context *);

#define HANDLE_FUNC(x)	[__KVM_HOST_SMCCC_FUNC_##x] = (hcall_t)handle_##x

static const hcall_t host_hcall[] = {
	HANDLE_FUNC(__kvm_vcpu_run),
	HANDLE_FUNC(__kvm_flush_vm_context),
	HANDLE_FUNC(__kvm_tlb_flush_vmid_ipa),
	HANDLE_FUNC(__kvm_tlb_flush_vmid),
	HANDLE_FUNC(__kvm_flush_cpu_context),
	HANDLE_FUNC(__kvm_timer_set_cntvoff),
	HANDLE_FUNC(__kvm_enable_ssbs),
	HANDLE_FUNC(__vgic_v3_get_gic_config),
	HANDLE_FUNC(__vgic_v3_read_vmcr),
	HANDLE_FUNC(__vgic_v3_write_vmcr),
	HANDLE_FUNC(__vgic_v3_init_lrs),
	HANDLE_FUNC(__kvm_get_mdcr_el2),
	HANDLE_FUNC(__vgic_v3_save_aprs),
	HANDLE_FUNC(__vgic_v3_restore_aprs),
	HANDLE_FUNC(__pkvm_init),
	HANDLE_FUNC(__pkvm_cpu_set_vector),
	HANDLE_FUNC(__pkvm_create_mappings),
	HANDLE_FUNC(__pkvm_create_private_mapping),
	HANDLE_FUNC(__pkvm_prot_finalize),
	HANDLE_FUNC(__pkvm_mark_hyp),
	HANDLE_FUNC(__pkvm_xchg_ro_pte),
	HANDLE_FUNC(__pkvm_cmpxchg_ro_pte),
	HANDLE_FUNC(__pkvm_assign_pgroot),
	HANDLE_FUNC(__pkvm_release_pgroot),
};

static void handle_host_hcall(struct kvm_cpu_context *host_ctxt)
{
	DECLARE_REG(unsigned long, id, host_ctxt, 0);
	hcall_t hfn;

	id -= KVM_HOST_SMCCC_ID(0);

	if (unlikely(id >= ARRAY_SIZE(host_hcall)))
		goto inval;

	hfn = host_hcall[id];
	if (unlikely(!hfn))
		goto inval;

	cpu_reg(host_ctxt, 0) = SMCCC_RET_SUCCESS;
	hfn(host_ctxt);

	return;
inval:
	cpu_reg(host_ctxt, 0) = SMCCC_RET_NOT_SUPPORTED;
}

static void default_host_smc_handler(struct kvm_cpu_context *host_ctxt)
{
	__kvm_hyp_host_forward_smc(host_ctxt);
}

static void handle_host_smc(struct kvm_cpu_context *host_ctxt)
{
	bool handled;

	handled = kvm_host_psci_handler(host_ctxt);
	if (!handled)
		default_host_smc_handler(host_ctxt);

	/* SMC was trapped, move ELR past the current PC. */
	kvm_skip_host_instr();
}

static void handle_host_sysreg(struct kvm_cpu_context *host_ctxt, u64 esr)
{
	u64 regval = cpu_reg(host_ctxt, (esr >> 5) & 0x1f);
	u32 reg = sys_reg((esr >> 20) & 3, (esr >> 14) & 0x7, (esr >> 10) & 0xf,
			  (esr >> 1) & 0xf, (esr >> 17) & 0x7);
	u64 addr;

	switch (reg) {
	default:
		hyp_panic();
		break;
	case SYS_SCTLR_EL1:
		write_sysreg(regval, SCTLR_EL1);
		break;
	case SYS_TTBR0_EL1:
		// TODO stage 2 protection of reserved_pg_dir
		// TODO elide double trap for pgd switch
		addr = regval & ~TTBR_ASID_MASK;
		if (addr != hyp_virt_to_phys(reserved_pg_dir) &&
		    !kvm_pgtable_stage2_is_pgroot(&host_kvm.pgt, addr)) {
			inject_external_abort(host_ctxt);
			break;
		}
		host_ctxt->sys_regs[TTBR0_EL1] = regval;
		write_sysreg(regval, TTBR0_EL1);
		break;
	case SYS_TTBR1_EL1:
		write_sysreg(regval, TTBR1_EL1);
		break;
	case SYS_TCR_EL1:
		write_sysreg(regval, TCR_EL1);
		break;
	case SYS_ESR_EL1:
		write_sysreg(regval, ESR_EL1);
		break;
	case SYS_FAR_EL1:
		write_sysreg(regval, FAR_EL1);
		break;
	case SYS_AFSR0_EL1:
		write_sysreg(regval, AFSR0_EL1);
		break;
	case SYS_AFSR1_EL1:
		write_sysreg(regval, AFSR1_EL1);
		break;
	case SYS_MAIR_EL1:
		write_sysreg(regval, MAIR_EL1);
		break;
	case SYS_AMAIR_EL1:
		write_sysreg(regval, AMAIR_EL1);
		break;
	case SYS_CONTEXTIDR_EL1:
		write_sysreg(regval, CONTEXTIDR_EL1);
		break;
	}
	kvm_skip_host_instr();
}

void handle_trap(struct kvm_cpu_context *host_ctxt)
{
	u64 esr = read_sysreg_el2(SYS_ESR);

	switch (ESR_ELx_EC(esr)) {
	case ESR_ELx_EC_HVC64:
		handle_host_hcall(host_ctxt);
		break;
	case ESR_ELx_EC_SMC64:
		handle_host_smc(host_ctxt);
		break;
	case ESR_ELx_EC_SVE:
		sysreg_clear_set(cptr_el2, CPTR_EL2_TZ, 0);
		isb();
		sve_cond_update_zcr_vq(ZCR_ELx_LEN_MASK, SYS_ZCR_EL2);
		break;
	case ESR_ELx_EC_IABT_LOW:
	case ESR_ELx_EC_DABT_LOW:
		handle_host_mem_abort(host_ctxt);
		break;
	case ESR_ELx_EC_SYS64:
		handle_host_sysreg(host_ctxt, esr);
		break;
	default:
		hyp_panic();
	}
}
