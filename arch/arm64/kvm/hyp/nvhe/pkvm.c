// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_mmu.h>
#include <asm/memory.h>

#include <nvhe/pkvm.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>

#include "../debug-pl011.h"

/*
 * Start the shadow table handle at the offset defined instead of at 0.
 * Mainly for sanity checking and debugging.
 */
#define HANDLE_OFFSET 0x1000

/*
 * Spinlock for protecting the shadow table related state.
 * Protects writes to shadow_table, num_shadow_entries, and next_shadow_alloc,
 * as well as reads and writes to last_shadow_core_lookup.
 */
DEFINE_HYP_SPINLOCK(shadow_lock);

/*
 * The table of shadow kvm entries for protected VMs in hyp.
 * Allocated at the initialization and setup of hyp.
 */
struct shadow_entry *shadow_table;

/* The current number of entries in the shadow table. */
int num_shadow_entries;

/* The next entry to try to allocate from. */
int next_shadow_alloc;

/*
 * An entry to use for cache vcpu core lookups.
 */
struct vcpu_core_entry {
	const struct kvm_vcpu *host_vcpu;
	struct kvm_vcpu_arch_core *core;
};

/*
 * A single-entry cache for the most recent vcpu core lookup on this cpu.
 *
 * Linux tries to schedule the same vcpu on the same cpu, because migration is
 * expensive. Therefore, the goal of this single entry cache is to keep the last
 * vcpu core looked up on this cpu.
 */
DEFINE_PER_CPU(struct vcpu_core_entry, last_shadow_core_lookup);

/*
 * Update the shadow vcpu core cache with latest successful vcpu core lookup.
 */
static void update_shadow_core_cache(const struct kvm_vcpu *host_vcpu,
				     struct kvm_vcpu_arch_core *core)
{
	struct vcpu_core_entry *entry = this_cpu_ptr(&last_shadow_core_lookup);

	entry->host_vcpu = host_vcpu;
	entry->core = core;
}

/*
 * Lookup the shadow core in the shadow cache.
 */
static struct kvm_vcpu_arch_core *
lookup_shadow_core_cache(const struct kvm_vcpu *host_vcpu)
{
	const struct vcpu_core_entry *entry =
		this_cpu_ptr(&last_shadow_core_lookup);

	if (likely(entry->host_vcpu == host_vcpu))
		return entry->core;

	return NULL;
}

/*
 * Return the shadow entry corresponding to the provided handle.
 */
static struct shadow_entry *get_shadow_entry(int shadow_handle)
{
	int shadow_index = shadow_handle - HANDLE_OFFSET;

	if (unlikely(shadow_index < 0 || shadow_index >= KVM_MAX_PVMS))
		return NULL;

	return &shadow_table[shadow_index];
}

/*
 * Return a pointer to the hyp's shadow kvm corresponding to the handle.
 */
static struct kvm *get_shadow_kvm(int shadow_handle)
{
	const struct shadow_entry *shadow_entry;

	shadow_entry = get_shadow_entry(shadow_handle);
	if (unlikely(!shadow_entry))
		return NULL;

	return shadow_entry->kvm;
}

/*
 * Return a pointer to the kvm struct's ith shadow core.
 */
static struct kvm_vcpu_arch_core *
get_shadow_core_ptr(const struct kvm *kvm, int i)
{
	/* Shadow cores are located immediately after the shadow kvm. */
	struct kvm_vcpu_arch_core *shadow_cores = (struct kvm_vcpu_arch_core *)
		       ((unsigned long)kvm + sizeof(*kvm));

	return &shadow_cores[i];
}

/*
 * Return a pointer to the hyp's shadow vcpu corresponding to the host's vcpu.
 */
struct kvm_vcpu_arch_core *hyp_get_shadow_core(const struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_arch_core *core;
	const struct kvm_vcpu *vcpu_hyp_va;
	const struct kvm *kvm;
	int vcpu_idx;
	int shadow_handle;

	core = lookup_shadow_core_cache(vcpu);
	if (likely(core))
		return core;

	/* Don't trust the host that this memory location is legit. */
	if (unlikely(
		    check_host_memory_addr((u64)vcpu, sizeof(*vcpu))))
		return NULL;

	vcpu_hyp_va = kern_hyp_va(vcpu);
	shadow_handle = vcpu_hyp_va->arch.core_state.pkvm.shadow_handle;
	vcpu_idx = vcpu_hyp_va->vcpu_idx;

	kvm = get_shadow_kvm(shadow_handle);
	if (unlikely(!kvm))
		return NULL;

	if (unlikely(vcpu_idx < 0 || vcpu_idx >= kvm->created_vcpus))
		return NULL;

	core = get_shadow_core_ptr(kvm, vcpu_idx);

	update_shadow_core_cache(vcpu, core);

	return core;
}

/*
 * Unmap the physical address range from the host's stage 2 mmu.
 *
 * Return 0 on success, negative error code on failure.
 */
static int stage2_unmap_host(unsigned long pa, size_t size)
{
	int ret;

	hyp_spin_lock(&host_kvm.lock);
	ret = kvm_pgtable_stage2_unmap(&host_kvm.pgt, pa, size);
	hyp_spin_unlock(&host_kvm.lock);

	return ret;
}

/*
 * Sanitize arch-dependent kvm shadow values.
 */
static void fix_kvm_arch(struct kvm_arch *arch)
{
	/*
	 * TODO: Decide on how we're handling s2 mmu for protected guests.
	 * For now do not use the shadow mmu.
	 */
	memset(&arch->mmu, 0, sizeof(arch->mmu));

	/* GIC and PMU are not supported for protected VMs. */
	memset(&arch->vgic, 0, sizeof(arch->vgic));
	arch->pmu_filter = NULL;
	arch->pmuver = 0;

	/* Set the hyp virtual address for the firmware slot. */
	arch->pkvm.firmware_slot = kern_hyp_va(arch->pkvm.firmware_slot);
}

/*
 * Fix and sanitize the values of the kvm donated by the host.
 */
static void fix_kvm(struct kvm *kvm)
{
	refcount_set(&kvm->users_count, 1);
	fix_kvm_arch(&kvm->arch);

	kvm->mm = NULL;

	memset(kvm->memslots, 0, sizeof(kvm->memslots));
	memset(kvm->vcpus, 0, sizeof(kvm->vcpus));
	memset(&kvm->vm_list, 0, sizeof(kvm->vm_list));
	memset(kvm->buses, 0, sizeof(kvm->buses));

#ifdef CONFIG_HAVE_KVM_EVENTFD
	memset(&kvm->irqfds, 0, sizeof(kvm->irqfds));
	memset(&kvm->ioeventfds, 0, sizeof(kvm->ioeventfds));
#endif

#ifdef CONFIG_KVM_MMIO
	kvm->coalesced_mmio_ring = 0;
	memset(&kvm->coalesced_zones, 0,
	       sizeof(kvm->coalesced_zones));
#endif

#ifdef CONFIG_HAVE_KVM_IRQCHIP
	kvm->irq_routing = NULL;
#endif

#ifdef CONFIG_HAVE_KVM_IRQFD
	memset(&kvm->irq_ack_notifier_list, 0,
	       sizeof(kvm->irq_ack_notifier_list));
#endif

#if defined(CONFIG_MMU_NOTIFIER) && defined(KVM_ARCH_WANT_MMU_NOTIFIER)
	memset(&kvm->mmu_notifier, 0, sizeof(kvm->mmu_notifier));
	kvm->mmu_notifier_count = 0;
#endif
	memset(&kvm->devices, 0, sizeof(kvm->devices));

	kvm->debugfs_dentry = NULL;
	kvm->debugfs_stat_data = NULL;
	memset(&kvm->srcu, 0, sizeof(kvm->srcu));
	memset(&kvm->irq_srcu, 0, sizeof(kvm->irq_srcu));
}

/*
 * Fix and sanitize the values of the shadow_core donated by the host.
 */
static void fix_core(struct kvm_vcpu_arch_core *shadow_core,
		     struct kvm *kvm)
{
	/* Associate the core with its kvm. */
	shadow_core->pkvm.shadow_handle = kvm->arch.pkvm.shadow_handle;
	shadow_core->pkvm.kvm = kvm;
}

/*
 * Fix and sanitize the values of the shadow_cores donated by the host, and
 * fix the corresponding pointer in the kvm.
 */
static void fix_cores(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->created_vcpus; i++) {
		struct kvm_vcpu_arch_core *shadow_core =
			get_shadow_core_ptr(kvm, i);

		fix_core(shadow_core, kvm);
		kvm->vcpus[i] =
			NULL; // TODO: might be useful to maintain
	}
}

/*
 * Fix and sanitize the values of the shadow state donated by the host.
 *
 * Ensures that all pointers are either mapped to a valid hyp address, or set to
 * NULL if not of interest to hyp.
 *
 * Return 0 on success, negative error code on failure.
 */
static int fix_shadow_structs(void *shadow_addr, size_t size)

{
	int num_vcpus;
	size_t expected_shadow_size;
	struct kvm *kvm = (struct kvm *)shadow_addr;

	num_vcpus = kvm->created_vcpus;
	if (num_vcpus < 1 || num_vcpus > KVM_MAX_VCPUS)
		return -EINVAL;

	/* Only use shadows for protected VMs. */
	if (!kvm_vm_is_protected(kvm))
		return -EINVAL;

	/*
	 * size is rounded up when allocated and donated by the host,
	 * so it's likely larger than the sum of the struct sizes.
	 */
	expected_shadow_size = sizeof(struct kvm) +
			       sizeof(struct kvm_vcpu_arch_core) * num_vcpus;
	if (size < expected_shadow_size)
		return -EINVAL;

	fix_kvm(kvm);
	fix_cores(kvm);

	return 0;
}

/*
 * Allocate a shadow table entry and insert a pointer to the shadow kvm.
 *
 * Return a unique handle to the protected VM on success,
 * negative error code on failure.
 */
static int insert_shadow_table(struct kvm *kvm,
			       const struct kvm *host_kvm,
			       size_t size)
{
	int ret;

	hyp_spin_lock(&shadow_lock);

	if (unlikely(num_shadow_entries >= KVM_MAX_PVMS)) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	/*
	 * Initializing protected state might have failed, yet a malicious host
	 * could trigger this function. Thus, ensure that shadow_table exists.
	 */
	if (unlikely(!shadow_table)) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/* Find the next free entry in the shadow table. */
	while (shadow_table[next_shadow_alloc].kvm)
		next_shadow_alloc = (next_shadow_alloc + 1) % KVM_MAX_PVMS;

	shadow_table[next_shadow_alloc] =
		(struct shadow_entry){ .kvm = kvm,
				       .size = size };
	ret = HANDLE_OFFSET + next_shadow_alloc;
	kvm->arch.pkvm.shadow_handle = ret;

	next_shadow_alloc = (next_shadow_alloc + 1) % KVM_MAX_PVMS;
	num_shadow_entries++;

out_unlock:
	hyp_spin_unlock(&shadow_lock);
	return ret;
}

/*
 * Deallocate and remove the shadow table entry corresponding to the handle.
 */
static void remove_shadow_table(struct shadow_entry *shadow_entry)
{
	if (!shadow_entry)
		return;

	hyp_spin_lock(&shadow_lock);

	memset(shadow_entry, 0, sizeof(*shadow_entry));
	num_shadow_entries--;

	hyp_spin_unlock(&shadow_lock);
}

/*
 * Initialize the shadow copy of the protected VM state using the memory
 * donated by the host.
 *
 * Unmaps the donated memory from the host at stage 2.
 *
 * Return a unique handle to the protected VM on success,
 * negative error code on failure.
 */
int __pkvm_init_shadow(const struct kvm *host_kvm,
		       void *host_shadow_va,
		       size_t size)
{
	void *hyp_shadow_addr = kern_hyp_va(host_shadow_va);
	void *hyp_shadow_end =
		(void *)((unsigned long)hyp_shadow_addr) + size;
	struct kvm *kvm = hyp_shadow_addr;
	const struct kvm *host_kvm_hyp = __hyp_pa(kern_hyp_va(host_kvm));
	unsigned long host_shadow_pa = __pa((unsigned long)host_shadow_va);
	int shadow_handle;
	int ret = 0;

	/* Don't automatically trust host-provided memory. */
	ret = check_host_memory_addr((u64)host_kvm, sizeof(*host_kvm));
	if (ret < 0)
		goto err;

	ret = check_host_memory_addr((u64)host_shadow_va, size);
	if (ret < 0)
		goto err;

	/* Only use shadows for protected VMs. */
	if (!kvm_vm_is_protected(host_kvm_hyp)) {
		ret = -EINVAL;
		goto err;
	}
	/* Unmap the donated shadow memory from the host's stage 2. */
	ret = stage2_unmap_host(host_shadow_pa, size);
	if (ret < 0)
		goto err;

	/* Shadow memory should be owned exclusively by hyp. */
	ret = __pkvm_mark_hyp(host_shadow_pa, host_shadow_pa + size);
	if (ret < 0)
		goto err;

	/* Create hyp mappings for the donated area. */
	ret = pkvm_create_mappings(hyp_shadow_addr, hyp_shadow_end, PAGE_HYP);
	if (ret < 0)
		goto err_mark_host;

	/* Add the entry to the shadow table. */
	ret = insert_shadow_table(kvm, host_kvm, size);
	if (ret < 0)
		goto err_remove_hyp_mappings;

	shadow_handle = ret;

	/* Fix and sanitize the data in shadow memory. */
	ret = fix_shadow_structs(hyp_shadow_addr, size);
	if (ret < 0)
		goto err_clear_shadow;

	return shadow_handle;

err_clear_shadow:
	/* Clear the donated shadow memory on failure to avoid data leaks. */
	memset(hyp_shadow_addr, 0, size);
	remove_shadow_table(get_shadow_entry(shadow_handle));

err_remove_hyp_mappings:
	/* TODO: Remove hyp mappings for the shadow area. */

err_mark_host:
	/* Return shadow memory ownership to the host. */
	__pkvm_mark_host(host_shadow_pa, host_shadow_pa + size);

err:
	return ret;
}

void __pkvm_teardown_shadow(const struct kvm *host_kvm)
{
	struct kvm *kvm;
	const struct kvm *host_kvm_hyp;
	struct shadow_entry *shadow_entry;
	size_t size;
	phys_addr_t shadow_kvm_pa;
	int shadow_handle;

	/* Don't trust the host that this memory location is legit. */
	if (unlikely(
		    check_host_memory_addr((u64)host_kvm, sizeof(*host_kvm))))
		return;

	host_kvm_hyp = kern_hyp_va(host_kvm);

	shadow_handle = host_kvm->arch.pkvm.shadow_handle;

	/* Lookup then remove entry from the shadow table. */
	shadow_entry = get_shadow_entry(shadow_handle);
	size = shadow_entry->size;
	kvm = shadow_entry->kvm;
	shadow_kvm_pa = __hyp_pa(kern_hyp_va(kvm));
	remove_shadow_table(shadow_entry);

	/* Clear the shadow memory since hyp is releasing it back to host. */
	memset(kvm, 0, size);

	/* TODO: Remove hyp mappings for the donated shadow area. */

	/* Return shadow memory ownership to the host. */
	__pkvm_mark_host(shadow_kvm_pa, shadow_kvm_pa + size);
}
