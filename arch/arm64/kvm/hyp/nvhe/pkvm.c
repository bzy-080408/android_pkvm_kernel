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

/*
 * Start the shadow table handle at the offset defined instead of at 0.
 * Mainly for sanity checking and debugging.
 */
#define HANDLE_OFFSET 0x1000

extern unsigned long hyp_nr_cpus;

/*
 * Spinlock for protecting the shadow table related state.
 * Protects writes to shadow_table, num_shadow_entries, and next_shadow_alloc,
 * as well as reads and writes to last_shadow_vcpu_lookup.
 * TODO: fix, not necessary for percpu cache
 */
DEFINE_HYP_SPINLOCK(shadow_lock);

/*
 * The table of shadow entries for protected VMs in hyp.
 * Allocated at hyp initialization and setup.
 */
struct shadow_memory_area *shadow_table;

/* Current number of vms in the shadow table. */
int num_shadow_entries;

/* The next entry index to try to allocate from. */
int next_shadow_alloc;

/*
 * Entry to use for cached lookups.
 */
struct vcpu_state_cache_entry {
	const struct kvm_vcpu *vcpu;
	struct shadow_vcpu_state *state;
};

/*
 * A single-entry cache for the most recent lookup on this cpu.
 *
 * Linux tries to schedule the same vcpu on the same cpu, because migration is
 * expensive. This single entry cache keeps the most recent lookup  performed on
 * this cpu.
 */
DEFINE_PER_CPU(struct vcpu_state_cache_entry, last_shadow_vcpu_lookup);

/*
 * Update the shadow vcpu lookup cache with latest successful lookup.
 */
static void update_shadow_vcpu_cache(const struct kvm_vcpu *vcpu,
				     struct shadow_vcpu_state *state)
{
	struct vcpu_state_cache_entry *entry =
		this_cpu_ptr(&last_shadow_vcpu_lookup);

	*entry = (struct vcpu_state_cache_entry){vcpu, state};
}

/*
 * Lookup the shadow vcpu state in the cache.
 */
static struct shadow_vcpu_state *
lookup_shadow_vcpu_cache(const struct kvm_vcpu *vcpu)
{
	const struct vcpu_state_cache_entry *entry =
		this_cpu_ptr(&last_shadow_vcpu_lookup);

	if (likely(entry->vcpu == vcpu))
		return entry->state;

	return NULL;
}

/*
 * Clear the shadow cache.
 */
void clear_shadow_cache(void)
{
	int i;

	for (i = 0; i < hyp_nr_cpus; i++) {
		// TODO: Is this safe?
		struct vcpu_state_cache_entry *entry =
			per_cpu_ptr(&last_shadow_vcpu_lookup, i);
		memset(entry, 0, sizeof(*entry));
	}
}

/*
 * Return the shadow memory area corresponding to the handle.
 */
static struct shadow_memory_area *get_shadow_memory(int shadow_handle)
{
	int shadow_index = shadow_handle - HANDLE_OFFSET;

	if (unlikely(shadow_index < 0 || shadow_index >= KVM_MAX_PVMS))
		return NULL;

	return &shadow_table[shadow_index];
}

/*
 * Return a pointer to the hyp's shadow vm from the shadow memory area;
 */
static inline struct kvm_shadow_vm *get_shadow_vm(void *shadow_addr)
{
	return shadow_addr + SHADOW_VM_OFFSET;
}

/*
 * Return a pointer to the ith shadow vcpu state.
 */
static struct shadow_vcpu_state *
get_shadow_vcpu_state(void *shadow_addr, int i)
{
	struct shadow_vcpu_state *shadow_vcpu_states =
		(struct shadow_vcpu_state *)
		       ((unsigned long)(shadow_addr) + SHADOW_VCPUS_OFFSET);

	return &shadow_vcpu_states[i];
}

/*
 * Returns the hyp shadow vcpu for the corresponding host vcpu,
 * or NULL if it fails.
 */
struct kvm_vcpu *hyp_get_shadow_vcpu(const struct kvm_vcpu *vcpu)
{
	struct shadow_vcpu_state *shadow_vcpu_state;
	struct shadow_memory_area *shadow_memory_area;
	int vcpu_idx;
	int shadow_handle;

	if (!kvm_vm_is_protected(kern_hyp_va(vcpu->kvm)))
		return NULL;

	shadow_vcpu_state = lookup_shadow_vcpu_cache(vcpu);
	if (likely(shadow_vcpu_state))
		return &shadow_vcpu_state->vcpu;

	shadow_handle = vcpu->arch.pkvm.shadow_handle;
	shadow_memory_area = get_shadow_memory(shadow_handle);
	vcpu_idx = vcpu->vcpu_idx;

	if (unlikely(vcpu_idx < 0 || vcpu_idx >= shadow_memory_area->num_vcpus))
		return NULL;

	shadow_vcpu_state =
		get_shadow_vcpu_state(shadow_memory_area->shadow_addr, vcpu_idx);
	update_shadow_vcpu_cache(vcpu, shadow_vcpu_state);

	return &shadow_vcpu_state->vcpu;
}

/*
 * Initialize and check the values of the shadow state donated by the host.
 *
 * Ensures that all pointers are either mapped to a valid hyp address, or set to
 * NULL if not of interest to hyp.
 *
 * Return 0 on success, negative error code on failure.
 */
static int init_shadow_structs(struct kvm *kvm,
			       void *shadow_addr,
			       size_t size,
			       int shadow_handle)
{
	int num_vcpus = kvm->created_vcpus;
	struct kvm_shadow_vm *vm = get_shadow_vm(shadow_addr);
	int i;

	vm->created_vcpus = num_vcpus;
	vm->shadow_handle = shadow_handle;

	/* TODO: initialize the protected MMU. For now, use the host's. */
	vm->mmu = &kvm->arch.mmu;

	for (i = 0; i < num_vcpus; i++) {
		struct shadow_vcpu_state *shadow_state =
			get_shadow_vcpu_state(shadow_addr, i);
		struct kvm_vcpu *shadow_vcpu = &shadow_state->vcpu;
		struct kvm_vcpu *host_vcpu = kern_hyp_va(kvm->vcpus[i]);

		shadow_state->vm = vm;
		shadow_vcpu->arch.hw_mmu = host_vcpu->arch.hw_mmu;
		shadow_vcpu->arch.pkvm.shadow_handle = shadow_handle;
		shadow_vcpu->arch.pkvm.host_vcpu = host_vcpu;
	}

	return 0;
}

/*
 * Allocate a shadow table entry and insert a pointer to the shadow area.
 *
 * Return a unique handle to the protected VM on success,
 * negative error code on failure.
 */
static int insert_shadow_table(void *shadow_addr,
			       int num_vcpus,
			       size_t shadow_size)
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
	while (shadow_table[next_shadow_alloc].shadow_addr)
		next_shadow_alloc = (next_shadow_alloc + 1) % KVM_MAX_PVMS;

	shadow_table[next_shadow_alloc] =
		(struct shadow_memory_area){ .shadow_addr = shadow_addr,
					     .num_vcpus = num_vcpus,
					     .shadow_size = shadow_size };
	ret = HANDLE_OFFSET + next_shadow_alloc;

	next_shadow_alloc = (next_shadow_alloc + 1) % KVM_MAX_PVMS;
	num_shadow_entries++;

out_unlock:
	hyp_spin_unlock(&shadow_lock);
	return ret;
}

/*
 * Deallocate and remove the shadow table entry corresponding to the handle.
 */
static void remove_shadow_table(struct shadow_memory_area *shadow_memory_area)
{
	if (!shadow_memory_area)
		return;


	hyp_spin_lock(&shadow_lock);

	/* Clear the shadow cache for all cpus. */
	// TODO: I think this should be done under lock and key to avoid race
	// conditions. Reason about it some more.
	clear_shadow_cache();

	memset(shadow_memory_area, 0, sizeof(*shadow_memory_area));
	num_shadow_entries--;

	hyp_spin_unlock(&shadow_lock);
}

/*
 * Checks whether the size of the area donated by the host is sufficient for
 * the shadow structues required for num_vcpus as well as the shadow vm.
 */
static int check_shadow_size(int num_vcpus, size_t shadow_size)
{
	if (num_vcpus < 1 || num_vcpus > KVM_MAX_VCPUS)
		return -EINVAL;

	/*
	 * Shadow size is rounded up when allocated and donated by the host,
	 * so it's likely to be larger than the sum of the struct sizes.
	 */
	if (shadow_size < hyp_get_shadow_size(num_vcpus))
		return -EINVAL;

	return 0;
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
int __pkvm_init_shadow(struct kvm *kvm,
		       void *shadow_va,
		       size_t shadow_size)
{
	void *shadow_addr = kern_hyp_va(shadow_va);
	unsigned long shadow_pa = __hyp_pa((unsigned long)shadow_addr);
	u64 pfn = hyp_phys_to_pfn(shadow_pa);
	u64 nr_pages = shadow_size >> PAGE_SHIFT;
	int shadow_handle;
	int ret = 0;

	/* Ensure the host has donated enough memory for the shadow structs. */
	kvm = kern_hyp_va(kvm);
	ret = check_shadow_size(kvm->created_vcpus, shadow_size);
	if (ret)
		goto err;

	ret = __pkvm_host_donate_hyp(pfn, nr_pages);
	if (ret)
		goto err;

	/* Add the entry to the shadow table. */
	ret = insert_shadow_table(shadow_addr, kvm->created_vcpus, shadow_size);
	if (ret < 0)
		goto err_remove_mappings;

	shadow_handle = ret;

	/* Initialize the data in shadow memory. */
	ret = init_shadow_structs(kvm, shadow_addr, shadow_size, shadow_handle);
	if (ret < 0)
		goto err_clear_shadow;

	return shadow_handle;

err_clear_shadow:
	/* Clear the donated shadow memory on failure to avoid data leaks. */
	memset(shadow_addr, 0, shadow_size);
	remove_shadow_table(get_shadow_memory(shadow_handle));

err_remove_mappings:
	WARN_ON(__pkvm_hyp_donate_host(pfn, nr_pages));

err:
	return ret;
}

void __pkvm_teardown_shadow(struct kvm *kvm)
{
	struct shadow_memory_area *shadow_memory_area;
	size_t shadow_size;
	int shadow_handle;
	void *shadow_addr;
	u64 pfn, nr_pages;

	kvm = kern_hyp_va(kvm);

	shadow_handle = kvm->arch.pkvm.shadow_handle;

	/* Lookup then remove entry from the shadow table. */
	shadow_memory_area = get_shadow_memory(shadow_handle);
	shadow_size = shadow_memory_area->shadow_size;
	shadow_addr = shadow_memory_area->shadow_addr;
	remove_shadow_table(shadow_memory_area);

	/* Clear the shadow memory since hyp is releasing it back to host. */
	memset(shadow_addr, 0, shadow_size);

	pfn = hyp_phys_to_pfn(__hyp_pa(shadow_addr));
	nr_pages = shadow_size >> PAGE_SHIFT;
	WARN_ON(__pkvm_hyp_donate_host(pfn, nr_pages));
}
