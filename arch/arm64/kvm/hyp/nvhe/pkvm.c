// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#include <linux/kvm_host.h>
#include <linux/mm.h>

#include <kvm/arm_hypercalls.h>
#include <kvm/arm_psci.h>

#include <nvhe/mem_protect.h>
#include <nvhe/memory.h>
#include <nvhe/pkvm.h>
#include <nvhe/trap_handler.h>

/* Used by icache_is_vpipt(). */
unsigned long __icache_flags;

/* Used by kvm_get_vttbr(). */
unsigned int kvm_arm_vmid_bits;

/*
 * The shadow state for the currently loaded vcpu. Used only when protected KVM
 * is enabled for both protected and non-protected VMs.
 */
static DEFINE_PER_CPU(struct kvm_shadow_vcpu_state *, loaded_shadow_state);

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
		mdcr_set |= MDCR_EL2_TDRA | MDCR_EL2_TDA;

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
	/*
	 * Always trap:
	 * - Feature id registers: to control features exposed to guests
	 * - Implementation-defined features
	 */
	vcpu->arch.hcr_el2 = HCR_GUEST_FLAGS |
			     HCR_TID3 | HCR_TACR | HCR_TIDCP | HCR_TID1;

	if (cpus_have_const_cap(ARM64_HAS_RAS_EXTN)) {
		/* route synchronous external abort exceptions to EL2 */
		vcpu->arch.hcr_el2 |= HCR_TEA;
		/* trap error record accesses */
		vcpu->arch.hcr_el2 |= HCR_TERR;
	}

	if (cpus_have_const_cap(ARM64_HAS_STAGE2_FWB))
		vcpu->arch.hcr_el2 |= HCR_FWB;

	if (cpus_have_const_cap(ARM64_MISMATCHED_CACHE_TYPE))
		vcpu->arch.hcr_el2 |= HCR_TID2;
}

/*
 * Initialize trap register values for protected VMs.
 */
static void pkvm_vcpu_init_traps(struct kvm_vcpu *shadow_vcpu, struct kvm_vcpu *host_vcpu)
{
	shadow_vcpu->arch.cptr_el2 = CPTR_EL2_DEFAULT;
	shadow_vcpu->arch.mdcr_el2 = 0;

	if (!vcpu_is_protected(shadow_vcpu)) {
		shadow_vcpu->arch.hcr_el2 = HCR_GUEST_FLAGS |
					    READ_ONCE(host_vcpu->arch.hcr_el2);
		return;
	}

	pvm_init_trap_regs(shadow_vcpu);
	pvm_init_traps_aa64pfr0(shadow_vcpu);
	pvm_init_traps_aa64pfr1(shadow_vcpu);
	pvm_init_traps_aa64dfr0(shadow_vcpu);
	pvm_init_traps_aa64mmfr0(shadow_vcpu);
	pvm_init_traps_aa64mmfr1(shadow_vcpu);
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
 * Spinlock for protecting the shadow table related state.
 * Protects writes to shadow_table, nr_shadow_entries, and next_shadow_alloc,
 * as well as reads and writes to last_shadow_vcpu_lookup.
 */
static DEFINE_HYP_SPINLOCK(shadow_lock);

/*
 * The table of shadow entries for protected VMs in hyp.
 * Allocated at hyp initialization and setup.
 */
static struct kvm_shadow_vm **shadow_table;

/* Current number of vms in the shadow table. */
static unsigned int nr_shadow_entries;

/* The next entry index to try to allocate from. */
static unsigned int next_shadow_alloc;

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

	/* Cannot load a new vcpu without putting the old one first. */
	if (__this_cpu_read(loaded_shadow_state))
		return NULL;

	hyp_spin_lock(&shadow_lock);
	vm = find_shadow_by_handle(shadow_handle);
	if (!vm || vm->kvm.created_vcpus <= vcpu_idx)
		goto unlock;

	shadow_state = &vm->shadow_vcpu_states[vcpu_idx];

	/* Ensure vcpu isn't loaded on more than one cpu simultaneously. */
	if (unlikely(shadow_state->loaded_shadow_state)) {
		shadow_state = NULL;
		goto unlock;
	}
	shadow_state->loaded_shadow_state = this_cpu_ptr(&loaded_shadow_state);

	hyp_page_ref_inc(hyp_virt_to_page(vm));
unlock:
	hyp_spin_unlock(&shadow_lock);

	__this_cpu_write(loaded_shadow_state, shadow_state);

	return shadow_state;
}

void pkvm_put_shadow_vcpu_state(struct kvm_shadow_vcpu_state *shadow_state)
{
	struct kvm_shadow_vm *vm = shadow_state->shadow_vm;

	hyp_spin_lock(&shadow_lock);
	shadow_state->loaded_shadow_state = NULL;
	__this_cpu_write(loaded_shadow_state, NULL);
	hyp_page_ref_dec(hyp_virt_to_page(vm));
	hyp_spin_unlock(&shadow_lock);
}

struct kvm_shadow_vcpu_state *pkvm_loaded_shadow_vcpu_state(void)
{
	return __this_cpu_read(loaded_shadow_state);
}

/* Check and copy the supported features for the vcpu from the host. */
static int copy_features(struct kvm_vcpu *shadow_vcpu, struct kvm_vcpu *host_vcpu)
{
	DECLARE_BITMAP(allowed_features, KVM_VCPU_MAX_FEATURES);

	bitmap_zero(allowed_features, KVM_VCPU_MAX_FEATURES);

	/*
	 * Always allowed:
	 * - CPU starting in poweroff state
	 * - PSCI v0.2
	 */
	set_bit(KVM_ARM_VCPU_POWER_OFF, allowed_features);
	set_bit(KVM_ARM_VCPU_PSCI_0_2, allowed_features);

	/*
	 * Check if remaining features are allowed:
	 * - Performance Monitoring
	 * - Scalable Vectors
	 * - Pointer Authentication
	 */
	if (FIELD_GET(ARM64_FEATURE_MASK(ID_AA64DFR0_PMUVER), PVM_ID_AA64DFR0_ALLOW))
		set_bit(KVM_ARM_VCPU_PMU_V3, allowed_features);

	if (FIELD_GET(ARM64_FEATURE_MASK(ID_AA64PFR0_SVE), PVM_ID_AA64PFR0_ALLOW))
		set_bit(KVM_ARM_VCPU_SVE, allowed_features);

	if (FIELD_GET(ARM64_FEATURE_MASK(ID_AA64ISAR1_API), PVM_ID_AA64ISAR1_ALLOW) &&
	    FIELD_GET(ARM64_FEATURE_MASK(ID_AA64ISAR1_APA), PVM_ID_AA64ISAR1_ALLOW))
		set_bit(KVM_ARM_VCPU_PTRAUTH_ADDRESS, allowed_features);

	if (FIELD_GET(ARM64_FEATURE_MASK(ID_AA64ISAR1_GPI), PVM_ID_AA64ISAR1_ALLOW) &&
	    FIELD_GET(ARM64_FEATURE_MASK(ID_AA64ISAR1_GPA), PVM_ID_AA64ISAR1_ALLOW))
		set_bit(KVM_ARM_VCPU_PTRAUTH_GENERIC, allowed_features);

	bitmap_and(shadow_vcpu->arch.features, host_vcpu->arch.features,
		allowed_features, KVM_VCPU_MAX_FEATURES);

	/*
	 * Check for system support for address/generic pointer authentication
	 * features if either are enabled.
	 */
	if ((test_bit(KVM_ARM_VCPU_PTRAUTH_ADDRESS, shadow_vcpu->arch.features) ||
	     test_bit(KVM_ARM_VCPU_PTRAUTH_GENERIC, shadow_vcpu->arch.features)) &&
	    !system_has_full_ptr_auth())
		return -EINVAL;

	return 0;
}

static void unpin_host_vcpus(struct kvm_shadow_vcpu_state *shadow_vcpu_states,
			     unsigned int nr_vcpus)
{
	int i;

	for (i = 0; i < nr_vcpus; i++) {
		struct kvm_vcpu *host_vcpu = shadow_vcpu_states[i].host_vcpu;
		hyp_unpin_shared_mem(host_vcpu, host_vcpu + 1);
	}
}

static int set_host_vcpus(struct kvm_shadow_vcpu_state *shadow_vcpu_states,
			  unsigned int nr_vcpus,
			  struct kvm_vcpu **vcpu_array,
			  size_t vcpu_array_size)
{
	int i;

	if (vcpu_array_size < sizeof(*vcpu_array) * nr_vcpus)
		return -EINVAL;

	for (i = 0; i < nr_vcpus; i++) {
		struct kvm_vcpu *host_vcpu = kern_hyp_va(vcpu_array[i]);

		if (hyp_pin_shared_mem(host_vcpu, host_vcpu + 1)) {
			unpin_host_vcpus(shadow_vcpu_states, i);
			return -EBUSY;
		}

		shadow_vcpu_states[i].host_vcpu = host_vcpu;
	}

	return 0;
}

static int init_shadow_psci(struct kvm_shadow_vm *vm,
			    struct kvm_shadow_vcpu_state *shadow_vcpu_state,
			    struct kvm_vcpu *host_vcpu)
{
	struct kvm_vcpu *shadow_vcpu = &shadow_vcpu_state->shadow_vcpu;
	struct vcpu_reset_state *reset_state = &shadow_vcpu->arch.reset_state;

	if (test_bit(KVM_ARM_VCPU_POWER_OFF, shadow_vcpu->arch.features)) {
		reset_state->reset = false;
		shadow_vcpu_state->power_state = PSCI_0_2_AFFINITY_LEVEL_OFF;
		return 0;
	}

	reset_state->pc = READ_ONCE(host_vcpu->arch.ctxt.regs.pc);
	reset_state->r0 = READ_ONCE(host_vcpu->arch.ctxt.regs.regs[0]);
	reset_state->reset = true;
	shadow_vcpu_state->power_state = PSCI_0_2_AFFINITY_LEVEL_ON_PENDING;

	return 0;
}

static int init_shadow_structs(struct kvm *kvm, struct kvm_shadow_vm *vm,
			       struct kvm_vcpu **vcpu_array,
			       unsigned int nr_vcpus)
{
	int i;
	int ret;

	vm->host_kvm = kvm;
	vm->kvm.created_vcpus = nr_vcpus;
	vm->kvm.arch.vtcr = host_kvm.arch.vtcr;
	vm->kvm.arch.pkvm.enabled = READ_ONCE(kvm->arch.pkvm.enabled);

	for (i = 0; i < nr_vcpus; i++) {
		struct kvm_shadow_vcpu_state *shadow_vcpu_state = &vm->shadow_vcpu_states[i];
		struct kvm_vcpu *shadow_vcpu = &shadow_vcpu_state->shadow_vcpu;
		struct kvm_vcpu *host_vcpu = shadow_vcpu_state->host_vcpu;

		shadow_vcpu_state->shadow_vm = vm;

		shadow_vcpu->kvm = &vm->kvm;
		shadow_vcpu->vcpu_id = READ_ONCE(host_vcpu->vcpu_id);
		shadow_vcpu->vcpu_idx = i;

		shadow_vcpu->arch.hw_mmu = &vm->kvm.arch.mmu;
		shadow_vcpu->arch.power_off = true;

		ret = copy_features(shadow_vcpu, host_vcpu);
		if (ret)
			return ret;

		pkvm_vcpu_init_traps(shadow_vcpu, host_vcpu);
		kvm_reset_pvm_sys_regs(shadow_vcpu);

		ret = init_shadow_psci(vm, shadow_vcpu_state, host_vcpu);
		if (ret)
			return ret;
	}

	return 0;
}

static bool __exists_shadow(struct kvm *host_kvm)
{
	int i;
	unsigned int nr_checked = 0;

	for (i = 0; i < KVM_MAX_PVMS && nr_checked < nr_shadow_entries; i++) {
		if (!shadow_table[i])
			continue;

		if (unlikely(shadow_table[i]->host_kvm == host_kvm))
			return true;

		nr_checked++;
	}

	return false;
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

	hyp_assert_lock_held(&shadow_lock);

	if (unlikely(nr_shadow_entries >= KVM_MAX_PVMS))
		return -ENOMEM;

	/*
	 * Initializing protected state might have failed, yet a malicious host
	 * could trigger this function. Thus, ensure that shadow_table exists.
	 */
	if (unlikely(!shadow_table))
		return -EINVAL;

	/* Check that a shadow hasn't been created before for this host KVM. */
	if (unlikely(__exists_shadow(kvm)))
		return -EEXIST;

	/* Find the next free entry in the shadow table. */
	while (shadow_table[next_shadow_alloc])
		next_shadow_alloc = (next_shadow_alloc + 1) % KVM_MAX_PVMS;
	shadow_handle = idx_to_shadow_handle(next_shadow_alloc);

	vm->kvm.arch.pkvm.shadow_handle = shadow_handle;
	vm->shadow_area_size = shadow_size;

	/* VMID 0 is reserved for the host */
	vmid = next_shadow_alloc + 1;
	if (vmid > 0xff)
		return -ENOMEM;

	atomic64_set(&mmu->vmid.id, vmid);
	mmu->arch = &vm->kvm.arch;
	mmu->pgt = &vm->pgt;

	shadow_table[next_shadow_alloc] = vm;
	next_shadow_alloc = (next_shadow_alloc + 1) % KVM_MAX_PVMS;
	nr_shadow_entries++;

	return shadow_handle;
}

/*
 * Deallocate and remove the shadow table entry corresponding to the handle.
 */
static void remove_shadow_table(unsigned int shadow_handle)
{
	hyp_assert_lock_held(&shadow_lock);
	shadow_table[shadow_handle_to_idx(shadow_handle)] = NULL;
	nr_shadow_entries--;
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

/*
 * Initialize the shadow copy of the protected VM state using the memory
 * donated by the host.
 *
 * Unmaps the donated memory from the host at stage 2.
 *
 * kvm: A pointer to the host's struct kvm (host va).
 * shadow_va: The host va of the area being donated for the shadow state.
 *	      Must be page aligned.
 * shadow_size: The size of the area being donated for the shadow state.
 *		Must be a multiple of the page size.
 * pgd: The host va of the area being donated for the stage-2 PGD for the VM.
 *	Must be page aligned. Its size is implied by the VM's VTCR.
 * Note: An array to the host KVM VCPUs (host VA) is passed via the pgd, as to
 *	 not to be dependent on how the VCPU's are layed out in struct kvm.
 *
 * Return a unique handle to the protected VM on success,
 * negative error code on failure.
 */
int __pkvm_init_shadow(struct kvm *kvm, void *shadow_va, size_t shadow_size,
		       void *pgd)
{
	struct kvm_shadow_vm *vm = kern_hyp_va(shadow_va);
	u64 nr_shadow_pages = shadow_size >> PAGE_SHIFT;
	unsigned int nr_vcpus;
	u64 nr_pgd_pages;
	size_t pgd_size;
	int ret;

	/* Check that the donated memory is aligned to page boundaries. */
	if (!PAGE_ALIGNED(shadow_va) ||
	    !PAGE_ALIGNED(shadow_size) ||
	    !PAGE_ALIGNED(pgd))
		return -EINVAL;

	kvm = kern_hyp_va(kvm);
	pgd = kern_hyp_va(pgd);

	ret = hyp_pin_shared_mem(kvm, kvm + 1);
	if (ret)
		return ret;

	nr_vcpus = READ_ONCE(kvm->created_vcpus);
	ret = check_shadow_size(nr_vcpus, shadow_size);
	if (ret)
		goto err_unpin_kvm;

	ret = __pkvm_host_donate_hyp(hyp_virt_to_pfn(vm), nr_shadow_pages);
	if (ret)
		goto err_unpin_kvm;

	/* Ensure donated shadow memory is cleared before using it. */
	memset(vm, 0, shadow_size);

	pgd_size = kvm_pgtable_stage2_pgd_size(host_kvm.arch.vtcr);
	nr_pgd_pages = pgd_size >> PAGE_SHIFT;
	ret = __pkvm_host_donate_hyp(hyp_virt_to_pfn(pgd), nr_pgd_pages);
	if (ret)
		goto err_remove_mappings;

	ret = set_host_vcpus(vm->shadow_vcpu_states, nr_vcpus, pgd, pgd_size);
	if (ret)
		goto err_remove_pgd;

	ret = init_shadow_structs(kvm, vm, pgd, nr_vcpus);
	if (ret < 0)
		goto err_unpin_host_vcpus;

	/* Add the entry to the shadow table. */
	hyp_spin_lock(&shadow_lock);
	ret = insert_shadow_table(kvm, vm, shadow_size);
	if (ret < 0)
		goto err_unlock_unpin_host_vcpus;

	ret = kvm_guest_prepare_stage2(vm, pgd);
	if (ret)
		goto err_remove_shadow_table;
	hyp_spin_unlock(&shadow_lock);

	return vm->kvm.arch.pkvm.shadow_handle;

err_remove_shadow_table:
	remove_shadow_table(vm->kvm.arch.pkvm.shadow_handle);
err_unlock_unpin_host_vcpus:
	hyp_spin_unlock(&shadow_lock);
err_unpin_host_vcpus:
	unpin_host_vcpus(vm->shadow_vcpu_states, nr_vcpus);
err_remove_pgd:
	WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(pgd), nr_pgd_pages));
err_remove_mappings:
	/* Clear the donated shadow memory on failure to avoid data leaks. */
	memset(vm, 0, shadow_size);
	WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(vm),
				       shadow_size >> PAGE_SHIFT));
err_unpin_kvm:
	hyp_unpin_shared_mem(kvm, kvm + 1);
	return ret;
}

int __pkvm_teardown_shadow(unsigned int shadow_handle)
{
	struct kvm_hyp_memcache *mc;
	struct kvm_shadow_vm *vm;
	size_t shadow_size;
	u64 nr_pages;
	void *addr;
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
	hyp_spin_unlock(&shadow_lock);

	/* Reclaim guest pages (including page-table pages) */
	mc = &vm->host_kvm->arch.pkvm.teardown_mc;
	reclaim_guest_pages(vm, mc);
	unpin_host_vcpus(vm->shadow_vcpu_states, vm->kvm.created_vcpus);

	/* Push the metadata pages to the teardown memcache */
	shadow_size = vm->shadow_area_size;
	hyp_unpin_shared_mem(vm->host_kvm, vm->host_kvm + 1);

	memset(vm, 0, shadow_size);
	for (addr = vm; addr < (void *)vm + shadow_size; addr += PAGE_SIZE)
		push_hyp_memcache(mc, addr, hyp_virt_to_phys);

	nr_pages = shadow_size >> PAGE_SHIFT;
	WARN_ON(__pkvm_hyp_donate_host(hyp_virt_to_pfn(vm), nr_pages));
	return 0;

err_unlock:
	hyp_spin_unlock(&shadow_lock);
	return err;
}

/*
 * This function sets the registers on the vcpu to their architecturally defined
 * reset values.
 *
 * Note: Can only be called by the vcpu on itself, after it has been turned on.
 */
void pkvm_reset_vcpu(struct kvm_shadow_vcpu_state *shadow_state)
{
	struct kvm_vcpu *vcpu = &shadow_state->shadow_vcpu;
	struct vcpu_reset_state *reset_state = &vcpu->arch.reset_state;

	WARN_ON(!reset_state->reset);

	if (test_bit(KVM_ARM_VCPU_PTRAUTH_ADDRESS, vcpu->arch.features) ||
	    test_bit(KVM_ARM_VCPU_PTRAUTH_GENERIC, vcpu->arch.features)) {
		/*
		 * This call should not fail since we've already checked for
		 * feature support on initialization.
		 */
		WARN_ON(kvm_vcpu_enable_ptrauth(vcpu));
	}

	memset(vcpu_gp_regs(vcpu), 0, sizeof(*vcpu_gp_regs(vcpu)));
	memset(&vcpu->arch.ctxt.fp_regs, 0, sizeof(vcpu->arch.ctxt.fp_regs));
	vcpu_gp_regs(vcpu)->pstate = VCPU_RESET_PSTATE_EL1;

	kvm_reset_pvm_sys_regs(vcpu);

	/* Propagate initiator's endianness, after kvm_reset_pvm_sys_regs. */
	if (reset_state->be)
		kvm_vcpu_set_be(vcpu);

	*vcpu_pc(vcpu) = reset_state->pc;
	vcpu_set_reg(vcpu, 0, reset_state->r0);

	reset_state->reset = false;

	shadow_state->exit_code = 0;

	WARN_ON(shadow_state->power_state != PSCI_0_2_AFFINITY_LEVEL_ON_PENDING);
	WRITE_ONCE(vcpu->arch.power_off, false);
	WRITE_ONCE(shadow_state->power_state, PSCI_0_2_AFFINITY_LEVEL_ON);
}

struct kvm_shadow_vcpu_state *pkvm_mpidr_to_vcpu_state(struct kvm_shadow_vm *vm, unsigned long mpidr)
{
	struct kvm_vcpu *vcpu;
	int i;

	mpidr &= MPIDR_HWID_BITMASK;

	for (i = 0; i < vm->kvm.created_vcpus; i++) {
		vcpu = &vm->shadow_vcpu_states[i].shadow_vcpu;

		if (mpidr == kvm_vcpu_get_mpidr_aff(vcpu))
			return &vm->shadow_vcpu_states[i];
	}

	return NULL;
}

/*
 * Returns true if the hypervisor has handled the PSCI call, and control should
 * go back to the guest, or false if the host needs to do some additional work
 * (i.e., wake up the vcpu).
 */
static bool pvm_psci_vcpu_on(struct kvm_vcpu *source_vcpu)
{
	struct kvm_shadow_vcpu_state *target_vcpu_state;
	struct kvm_shadow_vm *vm;
	struct vcpu_reset_state *reset_state;
	unsigned long cpu_id;
	unsigned long hvc_ret_val;
	int power_state;

	cpu_id = smccc_get_arg1(source_vcpu);
	if (!kvm_psci_valid_affinity(source_vcpu, cpu_id)) {
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;
		goto error;
	}

	vm = get_shadow_vm(source_vcpu);
	target_vcpu_state = pkvm_mpidr_to_vcpu_state(vm, cpu_id);

	/* Make sure the caller requested a valid vcpu. */
	if (!target_vcpu_state) {
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;
		goto error;
	}

	/*
	 * Make sure the requested vcpu is not on to begin with.
	 * Atomic to avoid race between vcpus trying to power on the same vcpu.
	 */
	power_state = cmpxchg(&target_vcpu_state->power_state,
		PSCI_0_2_AFFINITY_LEVEL_OFF,
		PSCI_0_2_AFFINITY_LEVEL_ON_PENDING);
	switch (power_state) {
	case PSCI_0_2_AFFINITY_LEVEL_ON_PENDING:
		hvc_ret_val = PSCI_RET_ON_PENDING;
		goto error;
	case PSCI_0_2_AFFINITY_LEVEL_ON:
		hvc_ret_val = PSCI_RET_ALREADY_ON;
		goto error;
	case PSCI_0_2_AFFINITY_LEVEL_OFF:
		break;
	default:
		hvc_ret_val = PSCI_RET_INTERNAL_FAILURE;
		goto error;
	}

	reset_state = &target_vcpu_state->shadow_vcpu.arch.reset_state;

	reset_state->pc = smccc_get_arg2(source_vcpu);
	reset_state->r0 = smccc_get_arg3(source_vcpu);

	/* Propagate caller endianness */
	reset_state->be = kvm_vcpu_is_be(source_vcpu);

	reset_state->reset = true;

	/*
	 * Return to the host, which should make the KVM_REQ_VCPU_RESET request
	 * as well as kvm_vcpu_wake_up() to schedule the vcpu.
	 */
	return false;

error:
	/* If there's an error go back straight to the guest. */
	smccc_set_retval(source_vcpu, hvc_ret_val, 0, 0, 0);
	return true;
}

static bool pvm_psci_vcpu_affinity_info(struct kvm_vcpu *vcpu)
{
	int i, matching_cpus = 0;
	unsigned long mpidr;
	unsigned long target_affinity;
	unsigned long target_affinity_mask;
	unsigned long lowest_affinity_level;
	struct kvm_shadow_vm *vm;
	unsigned long hvc_ret_val;

	target_affinity = smccc_get_arg1(vcpu);
	lowest_affinity_level = smccc_get_arg2(vcpu);

	if (!kvm_psci_valid_affinity(vcpu, target_affinity)) {
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;
		goto done;
	}

	/* Determine target affinity mask */
	target_affinity_mask = psci_affinity_mask(lowest_affinity_level);
	if (!target_affinity_mask) {
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;
		goto done;
	}

	vm = get_shadow_vm(vcpu);

	/* Ignore other bits of target affinity */
	target_affinity &= target_affinity_mask;

	hvc_ret_val = PSCI_0_2_AFFINITY_LEVEL_OFF;

	/*
	 * If at least one vcpu matching target affinity is ON then return ON,
	 * then if at least one is PENDING_ON then return PENDING_ON.
	 * Otherwise, return OFF.
	 */
	for (i = 0; i < vm->kvm.created_vcpus; i++) {
		struct kvm_shadow_vcpu_state *tmp = &vm->shadow_vcpu_states[i];

		mpidr = kvm_vcpu_get_mpidr_aff(&tmp->shadow_vcpu);

		if ((mpidr & target_affinity_mask) == target_affinity) {
			int power_state;

			matching_cpus++;
			power_state = READ_ONCE(tmp->power_state);
			switch (power_state) {
			case PSCI_0_2_AFFINITY_LEVEL_ON_PENDING:
				hvc_ret_val = PSCI_0_2_AFFINITY_LEVEL_ON_PENDING;
				break;
			case PSCI_0_2_AFFINITY_LEVEL_ON:
				hvc_ret_val = PSCI_0_2_AFFINITY_LEVEL_ON;
				goto done;
			case PSCI_0_2_AFFINITY_LEVEL_OFF:
				break;
			default:
				hvc_ret_val = PSCI_RET_INTERNAL_FAILURE;
				goto done;
			}
		}
	}

	if (!matching_cpus)
		hvc_ret_val = PSCI_RET_INVALID_PARAMS;

done:
	/* Nothing to be handled by the host. Go back to the guest. */
	smccc_set_retval(vcpu, hvc_ret_val, 0, 0, 0);
	return true;
}

/*
 * Returns true if the hypervisor has handled the PSCI call, and control should
 * go back to the guest, or false if the host needs to do some additional work
 * (e.g., turn off and update vcpu scheduling status).
 */
static bool pvm_psci_vcpu_off(struct kvm_vcpu *vcpu)
{
	struct kvm_shadow_vcpu_state *vcpu_state = get_shadow_state(vcpu);

	WARN_ON(vcpu->arch.power_off);
	WARN_ON(vcpu_state->power_state != PSCI_0_2_AFFINITY_LEVEL_ON);

	WRITE_ONCE(vcpu->arch.power_off, true);
	WRITE_ONCE(vcpu_state->power_state, PSCI_0_2_AFFINITY_LEVEL_OFF);

	/* Return to the host so that it can finish powering off the vcpu. */
	return false;
}

static bool pvm_psci_version(struct kvm_vcpu *vcpu)
{
	/* Nothing to be handled by the host. Go back to the guest. */
	smccc_set_retval(vcpu, KVM_ARM_PSCI_1_1, 0, 0, 0);
	return true;
}

static bool pvm_psci_not_supported(struct kvm_vcpu *vcpu)
{
	/* Nothing to be handled by the host. Go back to the guest. */
	smccc_set_retval(vcpu, PSCI_RET_NOT_SUPPORTED, 0, 0, 0);
	return true;
}

static bool pvm_psci_features(struct kvm_vcpu *vcpu)
{
	u32 feature = smccc_get_arg1(vcpu);
	unsigned long val;

	switch (feature) {
	case PSCI_0_2_FN_PSCI_VERSION:
	case PSCI_0_2_FN_CPU_SUSPEND:
	case PSCI_0_2_FN64_CPU_SUSPEND:
	case PSCI_0_2_FN_CPU_OFF:
	case PSCI_0_2_FN_CPU_ON:
	case PSCI_0_2_FN64_CPU_ON:
	case PSCI_0_2_FN_AFFINITY_INFO:
	case PSCI_0_2_FN64_AFFINITY_INFO:
	case PSCI_0_2_FN_SYSTEM_OFF:
	case PSCI_0_2_FN_SYSTEM_RESET:
	case PSCI_1_0_FN_PSCI_FEATURES:
	case PSCI_1_1_FN_SYSTEM_RESET2:
	case PSCI_1_1_FN64_SYSTEM_RESET2:
	case ARM_SMCCC_VERSION_FUNC_ID:
		val = PSCI_RET_SUCCESS;
		break;
	default:
		val = PSCI_RET_NOT_SUPPORTED;
		break;
	}

	/* Nothing to be handled by the host. Go back to the guest. */
	smccc_set_retval(vcpu, val, 0, 0, 0);
	return true;
}

static bool pkvm_handle_psci(struct kvm_vcpu *vcpu)
{
	u32 psci_fn = smccc_get_function(vcpu);

	switch (psci_fn) {
	case PSCI_0_2_FN_CPU_ON:
		kvm_psci_narrow_to_32bit(vcpu);
		fallthrough;
	case PSCI_0_2_FN64_CPU_ON:
		return pvm_psci_vcpu_on(vcpu);
	case PSCI_0_2_FN_CPU_OFF:
		return pvm_psci_vcpu_off(vcpu);
	case PSCI_0_2_FN_AFFINITY_INFO:
		kvm_psci_narrow_to_32bit(vcpu);
		fallthrough;
	case PSCI_0_2_FN64_AFFINITY_INFO:
		return pvm_psci_vcpu_affinity_info(vcpu);
	case PSCI_0_2_FN_PSCI_VERSION:
		return pvm_psci_version(vcpu);
	case PSCI_1_0_FN_PSCI_FEATURES:
		return pvm_psci_features(vcpu);
	case PSCI_0_2_FN_SYSTEM_RESET:
	case PSCI_0_2_FN_CPU_SUSPEND:
	case PSCI_0_2_FN64_CPU_SUSPEND:
	case PSCI_0_2_FN_SYSTEM_OFF:
	case PSCI_1_1_FN_SYSTEM_RESET2:
	case PSCI_1_1_FN64_SYSTEM_RESET2:
		return false; /* Handled by the host. */
	default:
		break;
	}

	return pvm_psci_not_supported(vcpu);
}

/*
 * Handler for protected VM HVC calls.
 *
 * Returns true if the hypervisor has handled the exit, and control should go
 * back to the guest, or false if it hasn't.
 */
bool kvm_handle_pvm_hvc64(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	u32 fn = smccc_get_function(vcpu);

	switch (fn) {
	case ARM_SMCCC_VERSION_FUNC_ID:
		/* Nothing to be handled by the host. Go back to the guest. */
		smccc_set_retval(vcpu, ARM_SMCCC_VERSION_1_1, 0, 0, 0);
		return true;
	default:
		return pkvm_handle_psci(vcpu);
	}
}
