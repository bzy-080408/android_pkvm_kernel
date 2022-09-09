// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#include <linux/kvm_host.h>
#include <linux/mm.h>
#include <nvhe/fixed_config.h>
#include <nvhe/mem_protect.h>
#include <nvhe/memory.h>
#include <nvhe/pkvm.h>
#include <nvhe/trap_handler.h>

/* Used by icache_is_vpipt(). */
unsigned long __icache_flags;

/* Used by kvm_get_vttbr(). */
unsigned int kvm_arm_vmid_bits;

/*
 * Set trap register values based on features in ID_AA64PFR0.
 */
static void pvm_init_traps_aa64pfr0(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64PFR0_EL1);
	u64 hcr_set = HCR_RW;
	u64 hcr_clear = 0;
	u64 cptr_set = 0;

	/* Protected KVM does not support AArch32 guests. */
	BUILD_BUG_ON(FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_EL0),
		PVM_ID_AA64PFR0_RESTRICT_UNSIGNED) != ID_AA64PFR0_ELx_64BIT_ONLY);
	BUILD_BUG_ON(FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_EL1),
		PVM_ID_AA64PFR0_RESTRICT_UNSIGNED) != ID_AA64PFR0_ELx_64BIT_ONLY);

	/*
	 * Linux guests assume support for floating-point and Advanced SIMD. Do
	 * not change the trapping behavior for these from the KVM default.
	 */
	BUILD_BUG_ON(!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_FP),
				PVM_ID_AA64PFR0_ALLOW));
	BUILD_BUG_ON(!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_ASIMD),
				PVM_ID_AA64PFR0_ALLOW));

	/* Trap RAS unless all current versions are supported */
	if (FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_RAS), feature_ids) <
	    ID_AA64PFR0_RAS_V1P1) {
		hcr_set |= HCR_TERR | HCR_TEA;
		hcr_clear |= HCR_FIEN;
	}

	/* Trap AMU */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_AMU), feature_ids)) {
		hcr_clear |= HCR_AMVOFFEN;
		cptr_set |= CPTR_EL2_TAM;
	}

	/* Trap SVE */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_SVE), feature_ids))
		cptr_set |= CPTR_EL2_TZ;

	vcpu->arch.hcr_el2 |= hcr_set;
	vcpu->arch.hcr_el2 &= ~hcr_clear;
	vcpu->arch.cptr_el2 |= cptr_set;
}

/*
 * Set trap register values based on features in ID_AA64PFR1.
 */
static void pvm_init_traps_aa64pfr1(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64PFR1_EL1);
	u64 hcr_set = 0;
	u64 hcr_clear = 0;

	/* Memory Tagging: Trap and Treat as Untagged if not supported. */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR1_MTE), feature_ids)) {
		hcr_set |= HCR_TID5;
		hcr_clear |= HCR_DCT | HCR_ATA;
	}

	vcpu->arch.hcr_el2 |= hcr_set;
	vcpu->arch.hcr_el2 &= ~hcr_clear;
}

/*
 * Set trap register values based on features in ID_AA64DFR0.
 */
static void pvm_init_traps_aa64dfr0(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64DFR0_EL1);
	u64 mdcr_set = 0;
	u64 mdcr_clear = 0;
	u64 cptr_set = 0;

	/* Trap/constrain PMU */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_PMUVER), feature_ids)) {
		mdcr_set |= MDCR_EL2_TPM | MDCR_EL2_TPMCR;
		mdcr_clear |= MDCR_EL2_HPME | MDCR_EL2_MTPME |
			      MDCR_EL2_HPMN_MASK;
	}

	/* Trap Debug */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_DEBUGVER), feature_ids))
		mdcr_set |= MDCR_EL2_TDRA | MDCR_EL2_TDA | MDCR_EL2_TDE;

	/* Trap OS Double Lock */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_DOUBLELOCK), feature_ids))
		mdcr_set |= MDCR_EL2_TDOSA;

	/* Trap SPE */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_PMSVER), feature_ids)) {
		mdcr_set |= MDCR_EL2_TPMS;
		mdcr_clear |= MDCR_EL2_E2PB_MASK << MDCR_EL2_E2PB_SHIFT;
	}

	/* Trap Trace Filter */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_TRACE_FILT), feature_ids))
		mdcr_set |= MDCR_EL2_TTRF;

	/* Trap Trace */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_TRACEVER), feature_ids))
		cptr_set |= CPTR_EL2_TTA;

	vcpu->arch.mdcr_el2 |= mdcr_set;
	vcpu->arch.mdcr_el2 &= ~mdcr_clear;
	vcpu->arch.cptr_el2 |= cptr_set;
}

/*
 * Set trap register values based on features in ID_AA64MMFR0.
 */
static void pvm_init_traps_aa64mmfr0(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64MMFR0_EL1);
	u64 mdcr_set = 0;

	/* Trap Debug Communications Channel registers */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64MMFR0_FGT), feature_ids))
		mdcr_set |= MDCR_EL2_TDCC;

	vcpu->arch.mdcr_el2 |= mdcr_set;
}

/*
 * Set trap register values based on features in ID_AA64MMFR1.
 */
static void pvm_init_traps_aa64mmfr1(struct kvm_vcpu *vcpu)
{
	const u64 feature_ids = pvm_read_id_reg(vcpu, SYS_ID_AA64MMFR1_EL1);
	u64 hcr_set = 0;

	/* Trap LOR */
	if (!FIELD_GET(ARM64_FEATURE_MASK(ID_AA64MMFR1_LOR), feature_ids))
		hcr_set |= HCR_TLOR;

	vcpu->arch.hcr_el2 |= hcr_set;
}

/*
 * Set baseline trap register values.
 */
static void pvm_init_trap_regs(struct kvm_vcpu *vcpu)
{
	const u64 hcr_trap_feat_regs = HCR_TID3;
	const u64 hcr_trap_impdef = HCR_TACR | HCR_TIDCP | HCR_TID1;

	/*
	 * Always trap:
	 * - Feature id registers: to control features exposed to guests
	 * - Implementation-defined features
	 */
	vcpu->arch.hcr_el2 |= hcr_trap_feat_regs | hcr_trap_impdef;

	/* Clear res0 and set res1 bits to trap potential new features. */
	vcpu->arch.hcr_el2 &= ~(HCR_RES0);
	vcpu->arch.mdcr_el2 &= ~(MDCR_EL2_RES0);
	vcpu->arch.cptr_el2 |= CPTR_NVHE_EL2_RES1;
	vcpu->arch.cptr_el2 &= ~(CPTR_NVHE_EL2_RES0);
}

/*
 * Initialize trap register values for protected VMs.
 */
void __pkvm_vcpu_init_traps(struct kvm_vcpu *vcpu)
{
	pvm_init_trap_regs(vcpu);
	pvm_init_traps_aa64pfr0(vcpu);
	pvm_init_traps_aa64pfr1(vcpu);
	pvm_init_traps_aa64dfr0(vcpu);
	pvm_init_traps_aa64mmfr0(vcpu);
	pvm_init_traps_aa64mmfr1(vcpu);
}

/*
 * Start the shadow table handle at the offset defined instead of at 0.
 * Mainly for sanity checking and debugging.
 */
#define HANDLE_OFFSET 0x1000

static unsigned int shadow_handle_to_idx(unsigned int shadow_handle)
{
	return shadow_handle - HANDLE_OFFSET;
}

static unsigned int idx_to_shadow_handle(unsigned int idx)
{
	return idx + HANDLE_OFFSET;
}

/*
 * Spinlock for protecting the shadow table related state.  Protects
 * writes to shadow_table and nr_shadow_entries as well as reads and
 * writes to last_shadow_vcpu_lookup.
 */
static DEFINE_HYP_SPINLOCK(shadow_lock);

/*
 * The table of shadow entries for protected VMs in hyp.
 * Allocated at hyp initialization and setup.
 */
static struct kvm_shadow_vm **shadow_table;

void hyp_shadow_table_init(void *tbl)
{
	WARN_ON(shadow_table);
	shadow_table = tbl;
}

/*
 * Return the shadow vm corresponding to the handle.
 */
static struct kvm_shadow_vm *find_shadow_by_handle(unsigned int shadow_handle)
{
	unsigned int shadow_idx = shadow_handle_to_idx(shadow_handle);

	if (unlikely(shadow_idx >= KVM_MAX_PVMS))
		return NULL;

	return shadow_table[shadow_idx];
}

struct kvm_shadow_vcpu_state *
pkvm_load_shadow_vcpu_state(unsigned int shadow_handle, unsigned int vcpu_idx)
{
	struct kvm_shadow_vcpu_state *shadow_state = NULL;
	struct kvm_shadow_vm *vm;

	hyp_spin_lock(&shadow_lock);
	vm = find_shadow_by_handle(shadow_handle);
	if (!vm || vm->nr_vcpus <= vcpu_idx)
		goto unlock;

	shadow_state = &vm->shadow_vcpu_states[vcpu_idx];
	hyp_page_ref_inc(hyp_virt_to_page(vm));
unlock:
	hyp_spin_unlock(&shadow_lock);
	return shadow_state;
}

void pkvm_put_shadow_vcpu_state(struct kvm_shadow_vcpu_state *shadow_state)
{
	struct kvm_shadow_vm *vm = shadow_state->shadow_vm;

	hyp_spin_lock(&shadow_lock);
	hyp_page_ref_dec(hyp_virt_to_page(vm));
	hyp_spin_unlock(&shadow_lock);
}

static void unpin_host_vcpu(struct kvm_shadow_vcpu_state *shadow_vcpu_state)
{
	struct kvm_vcpu *host_vcpu = shadow_vcpu_state->host_vcpu;

	if (host_vcpu)
		hyp_unpin_shared_mem(host_vcpu, host_vcpu + 1);
}

static void unpin_host_vcpus(struct kvm_shadow_vcpu_state *shadow_vcpu_states,
			     unsigned int nr_vcpus)
{
	int i;

	for (i = 0; i < nr_vcpus; i++)
		unpin_host_vcpu(&shadow_vcpu_states[i]);
}

static void init_shadow_vm(struct kvm *kvm,
			   struct kvm_shadow_vm *vm,
			   unsigned int nr_vcpus)
{
	vm->host_kvm = kvm;
	vm->kvm.created_vcpus = nr_vcpus;
	vm->kvm.arch.vtcr = host_kvm.arch.vtcr;
}

static int init_shadow_vcpu(struct kvm_shadow_vcpu_state *shadow_vcpu_state,
			    struct kvm_shadow_vm *vm,
			    struct kvm_vcpu *host_vcpu,
			    int vcpu_idx)
{
	struct kvm_vcpu *shadow_vcpu = &shadow_vcpu_state->shadow_vcpu;
	int ret = 0;

	host_vcpu = kern_hyp_va(host_vcpu);
	if (hyp_pin_shared_mem(host_vcpu, host_vcpu + 1))
		return -EBUSY;

	if (host_vcpu->vcpu_idx != vcpu_idx) {
		ret = -EINVAL;
		goto done;
	}

	shadow_vcpu_state->host_vcpu = host_vcpu;
	shadow_vcpu_state->shadow_vm = vm;

	shadow_vcpu->kvm = &vm->kvm;
	shadow_vcpu->vcpu_id = READ_ONCE(host_vcpu->vcpu_id);
	shadow_vcpu->vcpu_idx = vcpu_idx;

	shadow_vcpu->arch.hw_mmu = &vm->kvm.arch.mmu;
	shadow_vcpu->arch.cflags = READ_ONCE(host_vcpu->arch.cflags);
done:
	if (ret)
		unpin_host_vcpu(shadow_vcpu_state);
	return ret;
}

static int find_free_shadow_entry(struct kvm *host_kvm)
{
	int i, ret = -ENOMEM;

	for (i = 0; i < KVM_MAX_PVMS; ++i) {
		struct kvm_shadow_vm *vm = shadow_table[i];

		if (!vm) {
			if (ret < 0)
				ret = i;
			continue;
		}

		if (unlikely(vm->host_kvm == host_kvm)) {
			ret = -EEXIST;
			break;
		}
	}

	return ret;
}

/*
 * Allocate a shadow table entry and insert a pointer to the shadow vm.
 *
 * Return a unique handle to the protected VM on success,
 * negative error code on failure.
 */
static unsigned int insert_shadow_table(struct kvm *kvm,
					struct kvm_shadow_vm *vm,
					size_t shadow_size)
{
	struct kvm_s2_mmu *mmu = &vm->kvm.arch.mmu;
	unsigned int shadow_handle;
	unsigned int vmid;
	int shadow_idx;

	hyp_assert_lock_held(&shadow_lock);

	/*
	 * Initializing protected state might have failed, yet a malicious host
	 * could trigger this function. Thus, ensure that shadow_table exists.
	 */
	if (unlikely(!shadow_table))
		return -EINVAL;

	/* Find the next free entry in the shadow table. */
	shadow_idx = find_free_shadow_entry(kvm);
	if (shadow_idx < 0)
		return shadow_idx;

	shadow_handle = idx_to_shadow_handle(shadow_idx);
	vm->kvm.arch.pkvm.shadow_handle = shadow_handle;
	vm->shadow_area_size = shadow_size;

	/* VMID 0 is reserved for the host */
	vmid = shadow_idx + 1;
	atomic64_set(&mmu->vmid.id, vmid);

	mmu->arch = &vm->kvm.arch;
	mmu->pgt = &vm->pgt;

	shadow_table[shadow_idx] = vm;
	return shadow_handle;
}

/*
 * Deallocate and remove the shadow table entry corresponding to the handle.
 */
static void remove_shadow_table(unsigned int shadow_handle)
{
	hyp_assert_lock_held(&shadow_lock);
	shadow_table[shadow_handle_to_idx(shadow_handle)] = NULL;
}

static size_t pkvm_get_shadow_size(unsigned int nr_vcpus)
{
	/* Shadow space for the vm struct and all of its vcpu states. */
	return sizeof(struct kvm_shadow_vm) +
	       sizeof(struct kvm_shadow_vcpu_state) * nr_vcpus;
}

/*
 * Check whether the size of the area donated by the host is sufficient for
 * the shadow structures required for nr_vcpus as well as the shadow vm.
 */
static int check_shadow_size(unsigned int nr_vcpus, size_t shadow_size)
{
	if (nr_vcpus < 1 || nr_vcpus > KVM_MAX_VCPUS)
		return -EINVAL;

	/*
	 * Shadow size is rounded up when allocated and donated by the host,
	 * so it's likely to be larger than the sum of the struct sizes.
	 */
	if (shadow_size < pkvm_get_shadow_size(nr_vcpus))
		return -ENOMEM;

	return 0;
}

static void *map_donated_memory_noclear(unsigned long host_va, size_t size)
{
	void *va = (void *)kern_hyp_va(host_va);

	if (!PAGE_ALIGNED(va))
		return NULL;

	if (__pkvm_host_donate_hyp(hyp_virt_to_pfn(va),
				   PAGE_ALIGN(size) >> PAGE_SHIFT))
		return NULL;

	return va;
}

static void *map_donated_memory(unsigned long host_va, size_t size)
{
	void *va = map_donated_memory_noclear(host_va, size);

	if (va)
		memset(va, 0, size);

	return va;
}

static void __unmap_donated_memory(void *va, size_t size)
{
	WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(va),
				       PAGE_ALIGN(size) >> PAGE_SHIFT));
}

static void unmap_donated_memory(void *va, size_t size)
{
	if (!va)
		return;

	memset(va, 0, size);
	__unmap_donated_memory(va, size);
}

static void unmap_donated_memory_noclear(void *va, size_t size)
{
	if (!va)
		return;

	__unmap_donated_memory(va, size);
}

/*
 * Initialize the shadow copy of the protected VM state using the memory
 * donated by the host.
 *
 * Unmaps the donated memory from the host at stage 2.
 *
 * kvm: A pointer to the host's struct kvm (host va).
 * shadow_hva: The host va of the area being donated for the shadow state.
 *	       Must be page aligned.
 * shadow_size: The size of the area being donated for the shadow state.
 *		Must be a multiple of the page size.
 * pgd_hva: The host va of the area being donated for the stage-2 PGD for
 *	    the VM. Must be page aligned. Its size is implied by the VM's
 *	    VTCR.
 *
 * Return a unique handle to the protected VM on success,
 * negative error code on failure.
 */
int __pkvm_init_shadow(struct kvm *kvm, unsigned long shadow_hva,
		       size_t shadow_size, unsigned long pgd_hva)
{
	struct kvm_shadow_vm *vm = NULL;
	unsigned int nr_vcpus;
	size_t pgd_size = 0;
	void *pgd = NULL;
	int ret;

	kvm = kern_hyp_va(kvm);
	ret = hyp_pin_shared_mem(kvm, kvm + 1);
	if (ret)
		return ret;

	nr_vcpus = READ_ONCE(kvm->created_vcpus);
	ret = check_shadow_size(nr_vcpus, shadow_size);
	if (ret)
		goto err_unpin_kvm;

	ret = -ENOMEM;

	vm = map_donated_memory(shadow_hva, shadow_size);
	if (!vm)
		goto err_remove_mappings;

	pgd_size = kvm_pgtable_stage2_pgd_size(host_kvm.arch.vtcr);
	pgd = map_donated_memory_noclear(pgd_hva, pgd_size);
	if (!pgd)
		goto err_remove_mappings;

	init_shadow_vm(kvm, vm, nr_vcpus);

	/* Add the entry to the shadow table. */
	hyp_spin_lock(&shadow_lock);
	ret = insert_shadow_table(kvm, vm, shadow_size);
	if (ret < 0)
		goto err_unlock;

	ret = kvm_guest_prepare_stage2(vm, pgd);
	if (ret)
		goto err_remove_shadow_table;
	hyp_spin_unlock(&shadow_lock);

	return vm->kvm.arch.pkvm.shadow_handle;

err_remove_shadow_table:
	remove_shadow_table(vm->kvm.arch.pkvm.shadow_handle);
err_unlock:
	hyp_spin_unlock(&shadow_lock);
err_remove_mappings:
	unmap_donated_memory(vm, shadow_size);
	unmap_donated_memory_noclear(pgd, pgd_size);
err_unpin_kvm:
	hyp_unpin_shared_mem(kvm, kvm + 1);
	return ret;
}

/*
 * Initialize the protected vcpu state shadow copy in host-donated memory.
 *
 * shadow_handle: The handle for the protected vm.
 * host_vcpu: A pointer to the corresponding host vcpu (host va).
 *
 * Return 0 on success, negative error code on failure.
 */
int __pkvm_init_shadow_vcpu(unsigned int shadow_handle,
			    struct kvm_vcpu *host_vcpu)
{
	struct kvm_shadow_vm *vm;
	struct kvm_shadow_vcpu_state *shadow_vcpu_state;
	unsigned int idx;
	int ret;

	hyp_spin_lock(&shadow_lock);

	vm = find_shadow_by_handle(shadow_handle);
	if (!vm) {
		ret = -ENOENT;
		goto unlock;
	}

	idx = vm->nr_vcpus;
	if (idx >= vm->kvm.created_vcpus) {
		ret = -EINVAL;
		goto unlock;
	}

	shadow_vcpu_state = &vm->shadow_vcpu_states[idx];
	ret = init_shadow_vcpu(shadow_vcpu_state, vm, host_vcpu, idx);
	if (ret)
		goto unlock;

	vm->nr_vcpus++;
unlock:
	hyp_spin_unlock(&shadow_lock);
	return ret;
}

static void teardown_donated_memory(struct kvm_hyp_memcache *mc, void *addr, size_t size)
{
	memset(addr, 0, size);

	for (void *start = addr; start < addr + size; start += PAGE_SIZE)
		push_hyp_memcache(mc, start, hyp_virt_to_phys);

	unmap_donated_memory_noclear(addr, size);
}

int __pkvm_teardown_shadow(unsigned int shadow_handle)
{
	struct kvm_hyp_memcache *mc;
	struct kvm_shadow_vm *vm;
	unsigned int nr_vcpus;
	int err;

	/* Lookup then remove entry from the shadow table. */
	hyp_spin_lock(&shadow_lock);
	vm = find_shadow_by_handle(shadow_handle);
	if (!vm) {
		err = -ENOENT;
		goto err_unlock;
	}

	if (WARN_ON(hyp_page_count(vm))) {
		err = -EBUSY;
		goto err_unlock;
	}

	/* Ensure the VMID is clean before it can be reallocated */
	__kvm_tlb_flush_vmid(&vm->kvm.arch.mmu);
	remove_shadow_table(shadow_handle);
	nr_vcpus = vm->nr_vcpus;
	hyp_spin_unlock(&shadow_lock);

	/* Reclaim guest pages (including page-table pages) */
	mc = &vm->host_kvm->arch.pkvm.teardown_mc;
	reclaim_guest_pages(vm, mc);
	unpin_host_vcpus(vm->shadow_vcpu_states, nr_vcpus);

	hyp_unpin_shared_mem(vm->host_kvm, vm->host_kvm + 1);

	teardown_donated_memory(mc, vm, vm->shadow_area_size);
	return 0;

err_unlock:
	hyp_spin_unlock(&shadow_lock);
	return err;
}
