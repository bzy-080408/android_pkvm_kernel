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
static struct kvm_shadow_vm *get_shadow_vm(int shadow_handle)
{
	const struct shadow_entry *shadow_entry;

	shadow_entry = get_shadow_entry(shadow_handle);
	if (unlikely(!shadow_entry))
		return NULL;

	return shadow_entry->vm;
}

/*
 * Return a pointer to the kvm struct's ith shadow core.
 */
static struct kvm_vcpu_arch_core *
get_shadow_core_ptr(const struct kvm_shadow_vm *shadow_vm, int i)
{
	/* Shadow cores are located immediately after the shadow kvm. */
	struct kvm_vcpu_arch_core *shadow_cores = (struct kvm_vcpu_arch_core *)
		       ((unsigned long)shadow_vm + sizeof(*shadow_vm));

	return &shadow_cores[i];
}

/*
 * Return a pointer to the hyp's shadow vcpu corresponding to the host's vcpu.
 */
struct kvm_vcpu_arch_core *hyp_get_shadow_core(const struct kvm_vcpu *vcpu)
{
	struct kvm_vcpu_arch_core *core;
	const struct kvm_vcpu *vcpu_hyp_va;
	const struct kvm_shadow_vm *shadow_vm;
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

	shadow_vm = get_shadow_vm(shadow_handle);
	if (unlikely(!shadow_vm))
		return NULL;

	if (unlikely(vcpu_idx < 0 || vcpu_idx >= shadow_vm->created_vcpus))
		return NULL;

	core = get_shadow_core_ptr(shadow_vm, vcpu_idx);

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
 * Initialize and sanitize the shadow_vm donated by the host.
 */
static void fix_vm(const struct kvm *kvm, struct kvm_shadow_vm *shadow_vm)
{
	shadow_vm->created_vcpus = kvm->created_vcpus;

	/* TODO: initialize the protected MMU. For now, use the host's. */
	shadow_vm->mmu = &((struct kvm *)kvm)->arch.mmu;
}

/*
 * Fix and sanitize the values of the shadow_core donated by the host.
 */
static void fix_core(struct kvm_vcpu_arch_core *shadow_core,
		     struct kvm_shadow_vm *shadow_vm)
{
	/* Associate the core with its kvm. */
	shadow_core->pkvm.shadow_handle = shadow_vm->shadow_handle;
	shadow_core->pkvm.shadow_vm = shadow_vm;
}

/*
 * Fix and sanitize the values of the shadow_cores donated by the host, and
 * fix the corresponding pointer in the kvm.
 */
static void fix_cores(struct kvm_shadow_vm *shadow_vm)
{
	int i;

	for (i = 0; i < shadow_vm->created_vcpus; i++) {
		struct kvm_vcpu_arch_core *shadow_core =
			get_shadow_core_ptr(shadow_vm, i);

		fix_core(shadow_core, shadow_vm);
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
static int fix_shadow_structs(const struct kvm *kvm, void *shadow_addr, size_t size)

{
	int num_vcpus = kvm->created_vcpus;
	size_t expected_shadow_size;
	struct kvm_shadow_vm *shadow_vm = (struct kvm_shadow_vm *)shadow_addr;

	if (num_vcpus < 1 || num_vcpus > KVM_MAX_VCPUS)
		return -EINVAL;

	/*
	 * size is rounded up when allocated and donated by the host,
	 * so it's likely larger than the sum of the struct sizes.
	 */
	expected_shadow_size = sizeof(struct kvm_shadow_vm) +
			       sizeof(struct kvm_vcpu_arch_core) * num_vcpus;
	if (size < expected_shadow_size)
		return -EINVAL;

	fix_vm(kvm, shadow_vm);
	fix_cores(shadow_vm);

	return 0;
}

/*
 * Allocate a shadow table entry and insert a pointer to the shadow kvm.
 *
 * Return a unique handle to the protected VM on success,
 * negative error code on failure.
 */
static int insert_shadow_table(struct kvm_shadow_vm *shadow_vm,
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
	while (shadow_table[next_shadow_alloc].vm)
		next_shadow_alloc = (next_shadow_alloc + 1) % KVM_MAX_PVMS;

	shadow_table[next_shadow_alloc] =
		(struct shadow_entry){ .vm = shadow_vm, .size = size };
	ret = HANDLE_OFFSET + next_shadow_alloc;
	shadow_vm->shadow_handle = ret;

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
int __pkvm_init_shadow(const struct kvm *kvm, void *shadow_va, size_t size)
{
	void *hyp_shadow_addr = kern_hyp_va(shadow_va);
	void *hyp_shadow_end =
		(void *)((unsigned long)hyp_shadow_addr) + size;
	struct kvm_shadow_vm *shadow_vm = hyp_shadow_addr;
	unsigned long host_shadow_pa = __hyp_pa(kern_hyp_va(shadow_va));
	int shadow_handle;
	int ret = 0;

	/* Don't automatically trust host-provided memory. */
	ret = check_host_memory_addr((u64)kvm, sizeof(*kvm));
	if (ret < 0)
		goto err;

	ret = check_host_memory_addr((u64)shadow_va, size);
	if (ret < 0)
		goto err;

	kvm = kern_hyp_va(kvm);

	/* Only use shadows for protected VMs. */
	if (!kvm_vm_is_protected(kvm)) {
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
	ret = insert_shadow_table(shadow_vm, size);
	if (ret < 0)
		goto err_remove_hyp_mappings;

	shadow_handle = ret;

	/* Fix and sanitize the data in shadow memory. */
	ret = fix_shadow_structs(kvm, hyp_shadow_addr, size);
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

void __pkvm_teardown_shadow(const struct kvm *kvm)
{
	struct kvm_shadow_vm *shadow_vm;
	struct shadow_entry *shadow_entry;
	size_t size;
	phys_addr_t shadow_vm_pa;
	int shadow_handle;

	/* Don't automatically trust host-provided memory. */
	if (check_host_memory_addr((u64)kvm, sizeof(*kvm)) < 0)
		return;

	kvm = kern_hyp_va(kvm);

	/* Only use shadows for protected VMs. */
	if (!kvm_vm_is_protected(kvm))
		return;

	shadow_handle = kvm->arch.pkvm.shadow_handle;

	/* Lookup then remove entry from the shadow table. */
	shadow_entry = get_shadow_entry(shadow_handle);
	size = shadow_entry->size;
	shadow_vm = shadow_entry->vm;
	shadow_vm_pa = __hyp_pa(kern_hyp_va(shadow_vm));
	remove_shadow_table(shadow_entry);

	/* Clear the shadow memory since hyp is releasing it back to host. */
	memset(shadow_vm, 0, size);

	/* TODO: Remove hyp mappings for the donated shadow area. */

	/* Return shadow memory ownership to the host. */
	__pkvm_mark_host(shadow_vm_pa, shadow_vm_pa + size);
}
