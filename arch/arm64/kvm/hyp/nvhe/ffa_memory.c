// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC, Arm Ltd.
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include <asm/kvm_hyp.h>
#include <asm/kvm_pgtable.h>
#include <linux/align.h>
#include <linux/arm-smccc.h>
#include <linux/arm_ffa.h>
#include <linux/kvm_types.h>
#include <nvhe/ffa.h>
#include <nvhe/ffa_memory.h>
#include <nvhe/gfp.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/spinlock.h>

/* The maximum number of recipients a memory region may be sent to. */
#define MAX_MEM_SHARE_RECIPIENTS 1

/*
 * The maximum number of memory sharing handles which may be active at once. A
 * DONATE handle is active from when it is sent to when it is retrieved; a SHARE
 * or LEND handle is active from when it is sent to when it is reclaimed.
 */
#define MAX_MEM_SHARES 100

/*
 * The maximum number of fragments into which a memory sharing message may be
 * broken.
 */
#define MAX_FRAGMENTS 20

/**
 * struct ffa_memory_share_state - The state of a memory region which is being
 *                                 sent.
 * @handle: The handle assigned to the memory region.
 * @memory_region:
 *   The memory region being shared, or NULL if this share state
 *   is unallocated.
 * @fragments:
 *   An array of pointers to fragments of the memory region descriptor.
 * @fragment_constituent_counts: The number of constituents in each fragment.
 * @fragment_count:
 *   The number of valid elements in the @fragments and
 *   @fragment_constituent_counts arrays.
 * @share_func:
 *   The FF-A function used for sharing the memory. Must be one of
 *   FFA_MEM_DONATE, FFA_MEM_LEND or FFA_MEM_SHARE if the share state is
 *   allocated, or 0 if it is not allocated.
 * @sending_complete:
 *   True if all the fragments of this sharing request have been sent and pKVM
 *   has updated the sender page table accordingly.
 * @retrieved_fragment_count:
 *   How many fragments of the memory region each recipient has retrieved so
 *   far. The order of this array matches the order of the endpoint memory
 *   access descriptors in the memory region descriptor. Any entries beyond the
 *   ep_count will always be 0.
 */
struct ffa_memory_share_state {
	ffa_memory_handle_t handle;
	struct ffa_mem_region *memory_region;
	struct ffa_mem_region_addr_range *fragments[MAX_FRAGMENTS];
	uint32_t fragment_constituent_counts[MAX_FRAGMENTS];
	uint32_t fragment_count;
	uint32_t share_func;
	bool sending_complete;
	uint32_t retrieved_fragment_count[MAX_MEM_SHARE_RECIPIENTS];
};

/**
 * struct share_states_locked - Encapsulates the set of share states while the
 *                              ``share_states_lock`` is held.
 * @share_states: A pointer to the array of share states.
 */
struct share_states_locked {
	struct ffa_memory_share_state *share_states;
};

/*
 * All access to members of a `struct ffa_memory_share_state` must be guarded
 * by this lock.
 */
static hyp_spinlock_t share_states_lock_instance =
	(hyp_spinlock_t){ .__val = 0 };
static struct ffa_memory_share_state share_states[MAX_MEM_SHARES];

/*
 * Buffer for retrieving memory region information from the TEE for when a
 * region is reclaimed by a VM. Access to this buffer must be guarded by the VM
 * lock of the TEE VM.
 */
__aligned(PAGE_SIZE) static uint8_t
	tee_retrieve_buffer[MAILBOX_SIZE * MAX_FRAGMENTS];

/**
 * ffa_composite_constituent_offset() - Finds the offset of the first
 *                                      constituent of a memory region
 *                                      descriptor.
 * @memory_region: A memory region descriptor.
 * @receiver_index: The index of the reciver within the descriptor for which to
 *                  look up the offset. For now this must be 0.
 *
 * The caller must check that the receiver_index is within bounds, and that it
 * has a composite memory region offset.
 *
 * Return: the offset to the first constituent within the
 * @ffa_composite_mem_region for the given receiver from an
 * @ffa_mem_region.
 */
static inline uint32_t
ffa_composite_constituent_offset(struct ffa_mem_region *memory_region,
				 uint32_t receiver_index)
{
	BUG_ON(receiver_index >= memory_region->ep_count);
	BUG_ON(memory_region->ep_mem_access[receiver_index].composite_off == 0);

	return memory_region->ep_mem_access[receiver_index].composite_off +
	       sizeof(struct ffa_composite_mem_region);
}

/**
 * share_states_lock() - Takes the share states lock.
 *
 * Return: An object representing the locked share states.
 */
struct share_states_locked share_states_lock(void)
{
	hyp_spin_lock(&share_states_lock_instance);

	return (struct share_states_locked){ .share_states = share_states };
}

/**
 * share_states_unlock() - Releases the share states lock.
 * @share_states: An object previously returned by share_states_lock().
 */
static void share_states_unlock(struct share_states_locked *share_states)
{
	BUG_ON(share_states->share_states == NULL);
	share_states->share_states = NULL;
	hyp_spin_unlock(&share_states_lock_instance);
}

/**
 * allocate_share_state() - Initialises the next available ``struct
 *                          ffa_memory_share_state`` and sets
 *                          @share_state_ret to a pointer to it.
 * @share_states: The locked share states.
 * @share_func: The FF-A function ID used to send the memory region.
 * @memory_region: The FF-A memory region descriptor.
 * @fragment_length: The length of the first fragment of the memory region
 *                   descriptor.
 * @handle: At existing handle to use for the memory region, or
 *          ``FFA_MEMORY_HANDLE_INVALID``
 * @share_state_ret: A pointer to initialise to the newly-allocated share state.
 *
 * If @handle is ``FFA_MEMORY_HANDLE_INVALID`` then allocates an appropriate
 * handle, otherwise uses the provided handle which is assumed to be globally
 * unique.
 *
 * Return: true on success or false if none are available.
 */
static bool
allocate_share_state(struct share_states_locked share_states,
		     uint32_t share_func, struct ffa_mem_region *memory_region,
		     uint32_t fragment_length, ffa_memory_handle_t handle,
		     struct ffa_memory_share_state **share_state_ret)
{
	uint64_t i;

	BUG_ON(share_states.share_states == NULL);
	BUG_ON(memory_region == NULL);

	for (i = 0; i < MAX_MEM_SHARES; ++i) {
		if (share_states.share_states[i].share_func == 0) {
			uint32_t j;
			struct ffa_memory_share_state *allocated_state =
				&share_states.share_states[i];
			struct ffa_composite_mem_region *composite =
				ffa_memory_region_get_composite(memory_region,
								0);

			if (handle == FFA_MEMORY_HANDLE_INVALID) {
				allocated_state->handle =
					i |
					FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR;
			} else {
				allocated_state->handle = handle;
			}
			allocated_state->share_func = share_func;
			allocated_state->memory_region = memory_region;
			allocated_state->fragment_count = 1;
			allocated_state->fragments[0] = composite->constituents;
			allocated_state->fragment_constituent_counts[0] =
				(fragment_length -
				 ffa_composite_constituent_offset(memory_region,
								  0)) /
				sizeof(struct ffa_mem_region_addr_range);
			allocated_state->sending_complete = false;
			for (j = 0; j < MAX_MEM_SHARE_RECIPIENTS; ++j) {
				allocated_state->retrieved_fragment_count[j] =
					0;
			}
			if (share_state_ret != NULL)
				*share_state_ret = allocated_state;
			return true;
		}
	}

	return false;
}

/**
 * get_share_state() - Gets the share state for the given handle.
 * @share_states: A locked reference to the share states.
 * @handle: The memory region handle to look up.
 * @share_state_ret: A pointer to initialise to the share state if it is found.
 *
 * If the given @handle is a valid handle for an allocated share state then
 * initialises @share_state_ret to point to the share state and returns true.
 * Otherwise returns false.
 *
 * Return: whether a share state with the given handle was found.
 */
static bool get_share_state(struct share_states_locked share_states,
			    ffa_memory_handle_t handle,
			    struct ffa_memory_share_state **share_state_ret)
{
	struct ffa_memory_share_state *share_state;
	uint32_t index;

	BUG_ON(share_states.share_states == NULL);
	BUG_ON(share_state_ret == NULL);

	/*
	 * First look for a share_state allocated by us, in which case the
	 * handle is based on the index.
	 */
	if ((handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
	    FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR) {
		index = handle & ~FFA_MEMORY_HANDLE_ALLOCATOR_MASK;
		if (index < MAX_MEM_SHARES) {
			share_state = &share_states.share_states[index];
			if (share_state->share_func != 0) {
				*share_state_ret = share_state;
				return true;
			}
		}
	}

	/* Fall back to a linear scan. */
	for (index = 0; index < MAX_MEM_SHARES; ++index) {
		share_state = &share_states.share_states[index];
		if (share_state->handle == handle &&
		    share_state->share_func != 0) {
			*share_state_ret = share_state;
			return true;
		}
	}

	return false;
}

/**
 * share_state_free() - Marks a share state as unallocated.
 * @share_states: A locked reference to the share states.
 * @share_state: The share state to mark as unallocated.
 * @page_pool:
 *   The page pool into which to put pages freed from the memory region
 *   descriptor.
 */
static void share_state_free(struct share_states_locked share_states,
			     struct ffa_memory_share_state *share_state,
			     struct hyp_pool *page_pool)
{
	uint32_t i;

	BUG_ON(share_states.share_states == NULL);
	share_state->share_func = 0;
	share_state->sending_complete = false;
	hyp_put_page(page_pool, share_state->memory_region);
	/*
	 * First fragment is part of the same page as the `memory_region`, so it
	 * doesn't need to be freed separately.
	 */
	share_state->fragments[0] = NULL;
	share_state->fragment_constituent_counts[0] = 0;
	for (i = 1; i < share_state->fragment_count; ++i) {
		hyp_put_page(page_pool, share_state->fragments[i]);
		share_state->fragments[i] = NULL;
		share_state->fragment_constituent_counts[i] = 0;
	}
	share_state->fragment_count = 0;
	share_state->memory_region = NULL;
}

/**
 * share_state_sending_complete() - Checks whether the given share state has
 *                                  been fully sent.
 * @share_states: A locked reference to the share states.
 * @share_state: The share state to check.
 *
 * Return: whether the given share state has been fully sent.
 */
static bool
share_state_sending_complete(struct share_states_locked share_states,
			     struct ffa_memory_share_state *share_state)
{
	struct ffa_composite_mem_region *composite;
	uint32_t expected_constituent_count;
	uint32_t fragment_constituent_count_total = 0;
	uint32_t i;

	/* Lock must be held. */
	BUG_ON(share_states.share_states == NULL);

	/*
	 * Share state must already be valid, or it's not possible to get hold
	 * of it.
	 */
	BUG_ON(share_state->memory_region == NULL);
	BUG_ON(share_state->share_func == 0);

	composite =
		ffa_memory_region_get_composite(share_state->memory_region, 0);
	expected_constituent_count = composite->addr_range_cnt;
	for (i = 0; i < share_state->fragment_count; ++i) {
		fragment_constituent_count_total +=
			share_state->fragment_constituent_counts[i];
	}

	return fragment_constituent_count_total == expected_constituent_count;
}

/**
 * share_state_next_fragment_offset() - Calculates the offset of the next
 *                                      fragment expected for the given share
 *                                      state.
 * @share_states: A locked reference to the share states.
 * @share_state: The share state to check.
 *
 * Return: the offset in bytes.
 */
static uint32_t
share_state_next_fragment_offset(struct share_states_locked share_states,
				 struct ffa_memory_share_state *share_state)
{
	uint32_t next_fragment_offset;
	uint32_t i;

	/* Lock must be held. */
	BUG_ON(share_states.share_states == NULL);

	next_fragment_offset =
		ffa_composite_constituent_offset(share_state->memory_region, 0);
	for (i = 0; i < share_state->fragment_count; ++i) {
		next_fragment_offset +=
			share_state->fragment_constituent_counts[i] *
			sizeof(struct ffa_mem_region_addr_range);
	}

	return next_fragment_offset;
}

/* TODO: Add device attributes: GRE, cacheability, shareability. */
static inline enum kvm_pgtable_prot
ffa_memory_permissions_to_mode(ffa_memory_access_permissions_t permissions)
{
	enum kvm_pgtable_prot mode = 0;

	switch (ffa_get_data_access_attr(permissions)) {
	case FFA_DATA_ACCESS_RO:
		mode = KVM_PGTABLE_PROT_R;
		break;
	case FFA_DATA_ACCESS_RW:
	case FFA_DATA_ACCESS_NOT_SPECIFIED:
		mode = KVM_PGTABLE_PROT_R | KVM_PGTABLE_PROT_W;
		break;
	case FFA_DATA_ACCESS_RESERVED:
		pr_err("Tried to convert FFA_DATA_ACCESS_RESERVED.");
		BUG();
	}

	switch (ffa_get_instruction_access_attr(permissions)) {
	case FFA_INSTRUCTION_ACCESS_NX:
		break;
	case FFA_INSTRUCTION_ACCESS_X:
	case FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED:
		mode |= KVM_PGTABLE_PROT_X;
		break;
	case FFA_INSTRUCTION_ACCESS_RESERVED:
		pr_err("Tried to convert FFA_INSTRUCTION_ACCESS_RESVERVED.");
		BUG();
	}

	return mode;
}

struct get_mode_walk_data {
	enum kvm_pgtable_prot mode;
	bool got_mode;
};

static int get_mode_walker(hpa_t addr, hpa_t end, u32 level, kvm_pte_t *ptep,
			   enum kvm_pgtable_walk_flags flag, void *const arg)
{
	struct get_mode_walk_data *data = arg;

	if (!data->got_mode) {
		data->mode = kvm_pgtable_stage2_pte_prot(*ptep);
		data->got_mode = true;
	} else if (kvm_pgtable_stage2_pte_prot(*ptep) != data->mode) {
		return -1;
	}

	return 0;
}

/**
 * mm_vm_get_mode() - Gets the mode of the give range of intermediate physical
 *                    addresses if they are mapped with the same mode.
 * @vm_pgt: The stage-2 page table in which to check the pages.
 * @begin: The IPA of the beginning of the memory range to change.
 * @end: The IPA of the end of the memory range to check.
 * @mode: A pointer through which to store the mode of the pages, if they are
 *        consistent.
 *
 * Return: true if the range is mapped with the same mode and false otherwise.
 */
static bool mm_vm_get_mode(struct kvm_pgtable *vm_pgt, hpa_t begin, hpa_t end,
			   enum kvm_pgtable_prot *mode)
{
	struct get_mode_walk_data data = {
		.got_mode = false,
	};
	struct kvm_pgtable_walker walker = {
		.cb = get_mode_walker,
		.flags = KVM_PGTABLE_WALK_LEAF,
		.arg = &data,
	};
	int ret = kvm_pgtable_walk(vm_pgt, begin, end - begin, &walker);

	if (ret == 0 && data.got_mode) {
		*mode = data.mode;
		return true;
	} else {
		return false;
	}
}

/**
 * constituents_get_mode() - Gets the current mode of all the pages in the given
 *                           constituents.
 * @vm_pgt: The stage-2 page table in which to check the pages.
 * @orig_mode: A pointer through which to store the mode of the pages.
 * @fragments:
 *   An array of pointers to fragments of the memory region descriptor.
 * @fragment_constituent_counts:
 *   An array of the number of constituents in each fragment.
 * @fragment_count:
 *   The length of the @fragments and @fragment_constituent_counts arrays.
 *
 * Gets the current mode in the stage-2 page table of the given vm of all the
 * pages in the given constituents, if they all have the same mode, or return
 * an appropriate FF-A error if not.
 *
 * Context: The VM (i.e. host) page table must be locked while calling this
 * function.
 *
 * Return: FFA_SUCCESS, or an appropriate FFA_ERROR value.
 */
static struct arm_smccc_1_2_regs constituents_get_mode(
	struct kvm_pgtable *vm_pgt, enum kvm_pgtable_prot *orig_mode,
	struct ffa_mem_region_addr_range **fragments,
	const uint32_t *fragment_constituent_counts, uint32_t fragment_count)
{
	uint32_t i;
	uint32_t j;

	if (fragment_count == 0 || fragment_constituent_counts[0] == 0) {
		/*
		 * Fail if there are no constituents. Otherwise we would get an
		 * uninitialised *orig_mode.
		 */
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	for (i = 0; i < fragment_count; ++i) {
		for (j = 0; j < fragment_constituent_counts[i]; ++j) {
			hpa_t begin = fragments[i][j].address;
			size_t size = fragments[i][j].pg_cnt * FFA_PAGE_SIZE;
			hpa_t end = begin + size;
			enum kvm_pgtable_prot current_mode;

			/* Fail if addresses are not page-aligned. */
			if (!IS_ALIGNED(begin, PAGE_SIZE) ||
			    !IS_ALIGNED(end, PAGE_SIZE)) {
				return ffa_error(FFA_RET_INVALID_PARAMETERS);
			}

			/*
			 * Ensure that this constituent memory range is all
			 * mapped with the same mode.
			 */
			if (!mm_vm_get_mode(vm_pgt, begin, end,
					    &current_mode)) {
				return ffa_error(FFA_RET_DENIED);
			}

			/*
			 * Ensure that all constituents are mapped with the same
			 * mode.
			 */
			if (i == 0)
				*orig_mode = current_mode;
			else if (current_mode != *orig_mode)
				return ffa_error(FFA_RET_DENIED);
		}
	}

	return (struct arm_smccc_1_2_regs){ .a0 = FFA_SUCCESS };
}

/**
 * ffa_send_check_transition() - Checks that the pages of the memory region are
 *                               in an appropriate state to be sent as
 *                               requested.
 * @from_pgt: The page table of the sender, i.e. the host.
 * @share_func:
 *   The FF-A function used for sharing the memory. Must be one of
 *   FFA_MEM_DONATE, FFA_MEM_LEND or FFA_MEM_SHARE.
 * @required_from_mode:
 *   The minimum permissions which the sender must have for the memory region,
 *   because it is requesting to send it with these permissions.
 * @orig_from_mode:
 *   A pointer through which to store the permissions with which the sender had
 *   the memory region mapped before this operation, in case it needs to be
 *   rolled back.
 * @fragments:
 *   An array of pointers to fragments of the memory region descriptor.
 * @fragment_constituent_counts:
 *   An array of the number of constituents in each fragment.
 * @fragment_count:
 *   The length of the @fragments and @fragment_constituent_counts arrays.
 *
 * Verifies that all pages have the same mode, that the starting mode
 * constitutes a valid state and obtain the next mode to apply
 * to the sending VM.
 *
 * Context: The VM (i.e. host) page table must be locked while calling this
 * function.
 *
 * Return:
 *   * FFA_RET_DENIED if a state transition was not found;
 *   * FFA_RET_DENIED if the pages being shared do not have the same mode within
 *     the <from> VM;
 *   * FFA_RET_INVALID_PARAMETERS if the beginning and end IPAs are not page
 *     aligned;
 *   * FFA_RET_INVALID_PARAMETERS if the requested share type was not handled.
 *   * FFA_SUCCESS on success.
 */
static struct arm_smccc_1_2_regs
ffa_send_check_transition(struct kvm_pgtable *from_pgt, uint32_t share_func,
			  enum kvm_pgtable_prot required_from_mode,
			  enum kvm_pgtable_prot *orig_from_mode,
			  struct ffa_mem_region_addr_range **fragments,
			  uint32_t *fragment_constituent_counts,
			  uint32_t fragment_count)
{
	uint32_t i;
	uint32_t j;
	struct arm_smccc_1_2_regs ret;

	if (fragment_count == 0 || fragment_constituent_counts[0] == 0) {
		/*
		 * Fail if there are no constituents.
		 */
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	/*
	 * Check that transition is valid for all constituents, i.e. ensure that the sender is the
	 * owner and has exclusive access to the memory.
	 */
	for (i = 0; i < fragment_count; ++i) {
		for (j = 0; j < fragment_constituent_counts[i]; ++j) {
			hpa_t begin = fragments[i][j].address;
			size_t size = fragments[i][j].pg_cnt * FFA_PAGE_SIZE;
			int check_ret;

			switch (share_func) {
			case FFA_MEM_DONATE:
			case FFA_MEM_LEND:
				/*
				 * For now we treat lending the same as donating, because we don't
				 * have a state to track memory which has been lent.
				 */
				check_ret =
					__pkvm_host_check_donate_secure_world(
						begin, size);
				break;
			case FFA_MEM_SHARE:
				check_ret =
					__pkvm_host_check_share_secure_world(
						begin, size,
						required_from_mode);
				break;
			default:
				return ffa_error(FFA_RET_INVALID_PARAMETERS);
			}

			if (check_ret != 0) {
				pr_warn("Host tried to send memory in invalid state.");
				return ffa_error(FFA_RET_DENIED);
			}
		}
	}

	/* Get original mode in case we need to roll back. */
	ret = constituents_get_mode(from_pgt, orig_from_mode, fragments,
				    fragment_constituent_counts,
				    fragment_count);
	if (ret.a0 != FFA_SUCCESS) {
		pr_warn("Inconsistent modes.");
		return ret;
	}

	/* Ensure the address range is normal memory and not a device. */
	if (*orig_from_mode & KVM_PGTABLE_PROT_DEVICE) {
		pr_warn("Can't share device memory.");
		return ffa_error(FFA_RET_DENIED);
	}

	if ((*orig_from_mode & required_from_mode) != required_from_mode) {
		pr_warn("Sender tried to send memory with permissions which "
			"required mode it didn't have.");
		return ffa_error(FFA_RET_DENIED);
	}

	return (struct arm_smccc_1_2_regs){ .a0 = FFA_SUCCESS };
}

/**
 * ffa_region_group_identity_map() - Maps the given memory region into the
 *                                   stage-2 page table.
 * @vm_pgt:
 *   The stage-2 page table to update. For now only the host is supported.
 * @fragments:
 *   An array of pointers to fragments of the memory region descriptor.
 * @fragment_constituent_counts:
 *   An array of the number of constituents in each fragment.
 * @fragment_count:
 *   The length of the @fragments and @fragment_constituent_counts arrays.
 * @mode: The mode with which to map the pages.
 *
 * Updates the host's page table such that the given set of physical address
 * ranges are mapped in the address space at the corresponding address ranges,
 * in the mode provided.
 *
 * Return: true on success, or false if the update failed.
 */
static bool
ffa_region_group_identity_map(struct kvm_pgtable *vm_pgt,
			      struct ffa_mem_region_addr_range **fragments,
			      const uint32_t *fragment_constituent_counts,
			      uint32_t fragment_count,
			      enum kvm_pgtable_prot mode)
{
	uint32_t i;
	uint32_t j;

	/* Iterate over the memory region constituents within each fragment. */
	for (i = 0; i < fragment_count; ++i) {
		for (j = 0; j < fragment_constituent_counts[i]; ++j) {
			size_t size = fragments[i][j].pg_cnt * FFA_PAGE_SIZE;
			/* Host uses 1:1 mapping, so PAs are the same as IPAs. */
			phys_addr_t pa_begin = fragments[i][j].address;

			if (host_stage2_idmap_locked(pa_begin, size, mode) !=
			    0) {
				return false;
			}
		}
	}

	return true;
}

/**
 * clear_memory() - Clears a range of physical memory by overwriting it with
 *                  zeros.
 * @begin: The PA of the start of the memory range.
 * @size: The size of the memory range in bytes.
 *
 * The data is flushed from the cache so the memory has been cleared across the
 * system.
 *
 * Context: Assumes the memory is not currently mapped into the hypervisor's
 * page table, so will map it and unmap it automatically.
 *
 * Return: true if the memory was successfully cleared, false if we failed to
 * map it.
 */
static bool clear_memory(phys_addr_t begin, size_t size)
{
	void *ptr = hyp_map(begin, size, KVM_PGTABLE_PROT_W);

	if (!ptr)
		return false;

	memset(ptr, 0, size);
	kvm_flush_dcache_to_poc(ptr, size);
	BUG_ON(hyp_unmap(begin, size) != 0);

	return true;
}

/**
 * ffa_clear_memory_constituents() - Clears a region of physical memory by
 *                                   overwriting it with zeros.
 * @fragments:
 *   An array of pointers to fragments of the memory region descriptor.
 * @fragment_constituent_counts: The number of constituents in each fragment.
 * @fragment_count:
 *   The number of valid elements in the @fragments and
 *   @fragment_constituent_counts arrays.
 *
 * The data is flushed from the cache so the memory has been cleared across the
 * system.
 *
 * Context: Assumes the memory is not currently mapped into the hypervisor's
 * page table, so will map it and unmap it automatically.
 *
 * Return: true if the memory was successfully cleared, false if we failed to
 * map it.
 */
static bool
ffa_clear_memory_constituents(struct ffa_mem_region_addr_range **fragments,
			      const uint32_t *fragment_constituent_counts,
			      uint32_t fragment_count)
{
	uint32_t i;

	/* Iterate over the memory region constituents within each fragment. */
	for (i = 0; i < fragment_count; ++i) {
		uint32_t j;

		for (j = 0; j < fragment_constituent_counts[j]; ++j) {
			size_t size = fragments[i][j].pg_cnt * FFA_PAGE_SIZE;
			/* Host uses 1:1 mapping, so PAs are the same as IPAs. */
			phys_addr_t begin = fragments[i][j].address;

			if (!clear_memory(begin, size))
				return false;
		}
	}

	return true;
}

/**
 * ffa_send_check_update() - Validates and prepares memory to be sent from the
 *                           calling partition to another.
 * @from_pgt: The page table of the sender, i.e. the host.
 * @fragments:
 *   An array of pointers to fragments of the memory region descriptor.
 * @fragment_constituent_counts:
 *   An array of the number of constituents in each fragment.
 * @fragment_count:
 *   The length of the @fragments and @fragment_constituent_counts arrays.
 * @share_func:
 *   The FF-A function used for sharing the memory. Must be one of
 *   FFA_MEM_DONATE, FFA_MEM_LEND or FFA_MEM_SHARE.
 * @permissions: The permissions with which to share the region.
 * @clear: Whether to zero the memory region before sending it on.
 * @orig_from_mode_ret:
 *   If this is non-null, it is set to the original mode ofthe memory region
 *   before sharing. This can be used to roll back the share operation if
 *   needed.
 *
 * Context: This function requires the calling context to hold the <from> VM
 * lock.
 *
 * Return:
 *  In case of error, one of the following values is returned:
 *   * FFA_RET_INVALID_PARAMETERS - The endpoint provided parameters were
 *     erroneous;
 *   * FFA_RET_NO_MEMORY - pKVM did not have sufficient memory to complete the
 *     request.
 *   * FFA_RET_DENIED - The sender doesn't have sufficient access to send the
 *     memory with the given permissions.
 *  Success is indicated by FFA_SUCCESS.
 */
static struct arm_smccc_1_2_regs
ffa_send_check_update(struct kvm_pgtable *from_pgt,
		      struct ffa_mem_region_addr_range **fragments,
		      uint32_t *fragment_constituent_counts,
		      uint32_t fragment_count, uint32_t share_func,
		      ffa_memory_access_permissions_t permissions, bool clear,
		      enum kvm_pgtable_prot *orig_from_mode_ret)
{
	uint32_t i;
	uint32_t j;
	struct arm_smccc_1_2_regs ret;
	enum kvm_pgtable_prot orig_from_mode;
	const enum kvm_pgtable_prot permissions_mode =
		ffa_memory_permissions_to_mode(permissions);

	/*
	 * Make sure constituents are properly aligned to a 64-bit boundary. If
	 * not we would get alignment faults trying to read (64-bit) values.
	 */
	for (i = 0; i < fragment_count; ++i) {
		if (!IS_ALIGNED((uintptr_t)fragments[i], 8)) {
			pr_warn("Constituents not aligned.");
			return ffa_error(FFA_RET_INVALID_PARAMETERS);
		}
	}

	/*
	 * Check if the state transition is lawful for the sender, ensure that
	 * all constituents of a memory region being shared are at the same
	 * state.
	 */
	ret = ffa_send_check_transition(from_pgt, share_func, permissions_mode,
					&orig_from_mode, fragments,
					fragment_constituent_counts,
					fragment_count);
	if (ret.a0 != FFA_SUCCESS) {
		pr_warn("Invalid transition for send.");
		return ret;
	}

	if (orig_from_mode_ret != NULL)
		*orig_from_mode_ret = orig_from_mode;

	/*
	 * Update the mapping for the sender.
	 */
	for (i = 0; i < fragment_count; ++i) {
		for (j = 0; j < fragment_constituent_counts[i]; ++j) {
			hpa_t begin = fragments[i][j].address;
			size_t size = fragments[i][j].pg_cnt * FFA_PAGE_SIZE;
			int update_ret;

			switch (share_func) {
			case FFA_MEM_DONATE:
			case FFA_MEM_LEND:
				/*
				 * For now we treat lending the same as donating, because we don't
				 * have a state to track memory which has been lent.
				 */
				update_ret = __pkvm_host_donate_secure_world(
					begin, size);
				break;
			case FFA_MEM_SHARE:
				update_ret = __pkvm_host_share_secure_world(
					begin, size, permissions_mode);
				break;
			default:
				return ffa_error(FFA_RET_INVALID_PARAMETERS);
			}

			if (update_ret != 0) {
				pr_err("Failed to update host page table for sending memory.");
				ret = ffa_error(FFA_RET_NO_MEMORY);
				// TODO: Roll back partial update.
				goto out;
			}
		}
	}

	/* Clear the memory so no VM or device can see the previous contents. */
	if (clear && !ffa_clear_memory_constituents(fragments,
						    fragment_constituent_counts,
						    fragment_count)) {
		/*
		 * On failure, roll back by returning memory to the sender.
		 */
		BUG_ON(!ffa_region_group_identity_map(
			from_pgt, fragments, fragment_constituent_counts,
			fragment_count, orig_from_mode));

		ret = ffa_error(FFA_RET_NO_MEMORY);
		goto out;
	}

	ret = (struct arm_smccc_1_2_regs){ .a0 = FFA_SUCCESS };

out:
	/*
	 * Tidy up the page table by reclaiming failed mappings (if there was an
	 * error) or merging entries into blocks where possible (on success).
	 */
	// TODO: Defragment by coalescing page mappings into block mappings.

	return ret;
}

/**
 * ffa_memory_send_complete() - Completes a memory sending operation.
 * @from_pgt: The page table of the sender, i.e. the host.
 * @share_states: A locked reference to the share states.
 * @share_state: The share state for the operation.
 * @page_pool:
 *   The page pool into which to put pages freed from the memory region
 *   descriptor, if the operation fails.
 * @orig_from_mode_ret:
 *   A pointer through which to store the permissions with which the sender had
 *   the memory region mapped before this operation, in case it needs to be
 *   rolled back.
 *
 * Completes a memory sending operation by checking that it is valid, updating
 * the sender page table, and then either marking the share state as having
 * completed sending (on success) or freeing it (on failure).
 *
 * Return: FFA_SUCCESS with the handle encoded, or the relevant FFA_ERROR.
 */
static struct arm_smccc_1_2_regs ffa_memory_send_complete(
	struct kvm_pgtable *from_pgt, struct share_states_locked share_states,
	struct ffa_memory_share_state *share_state, struct hyp_pool *page_pool,
	enum kvm_pgtable_prot *orig_from_mode_ret)
{
	struct ffa_mem_region *memory_region = share_state->memory_region;
	struct arm_smccc_1_2_regs ret;

	/* Lock must be held. */
	BUG_ON(share_states.share_states == NULL);

	/* Check that state is valid in sender page table and update. */
	ret = ffa_send_check_update(
		from_pgt, share_state->fragments,
		share_state->fragment_constituent_counts,
		share_state->fragment_count, share_state->share_func,
		memory_region->ep_mem_access[0].attrs,
		memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR,
		orig_from_mode_ret);
	if (ret.a0 != FFA_SUCCESS) {
		/*
		 * Free share state, it failed to send so it can't be retrieved.
		 */
		pr_warn("Complete failed, freeing share state.");
		share_state_free(share_states, share_state, page_pool);
		return ret;
	}

	share_state->sending_complete = true;

	return ffa_mem_success(share_state->handle);
}

/**
 * ffa_memory_send_validate() - Validate the given memory region for a memory
 *                              send request.
 * @memory_region: The first fragment of the memory region descriptor.
 * @memory_share_length: The length of the entire memory region descriptor.
 * @fragment_length:
 *   The length of the first fragment of the memory region descriptor.
 * @share_func:
 *   The FF-A function used for sharing the memory. Must be one of
 *   FFA_MEM_DONATE, FFA_MEM_LEND or FFA_MEM_SHARE.
 * @permissions:
 *   Pointer through which to store the access permissions of the memory send
 *   request. Must not be NULL.
 *
 * Checks that the given `memory_region` represents a valid memory send request
 * of the given `share_func` type, return the clear flag and permissions via the
 * respective output parameters, and update the permissions if necessary.
 *
 * Return: FFA_SUCCESS if the request was valid, or the relevant FFA_ERROR if
 * not.
 */
static struct arm_smccc_1_2_regs
ffa_memory_send_validate(struct ffa_mem_region *memory_region,
			 uint32_t memory_share_length, uint32_t fragment_length,
			 uint32_t share_func,
			 ffa_memory_access_permissions_t *permissions)
{
	struct ffa_composite_mem_region *composite;
	uint32_t receivers_length;
	uint32_t constituents_offset;
	uint32_t constituents_length;
	enum ffa_data_access data_access;
	enum ffa_instruction_access instruction_access;

	BUG_ON(permissions == NULL);

	/*
	 * This should already be checked by the caller, just making the
	 * assumption clear here.
	 */
	BUG_ON(memory_region->ep_count != 1);

	/* The sender must match the message sender. */
	if (memory_region->sender_id != HOST_VM_ID)
		return ffa_error(FFA_RET_INVALID_PARAMETERS);

	/*
	 * Ensure that the composite header is within the memory bounds and
	 * doesn't overlap the first part of the message.
	 */
	receivers_length = sizeof(struct ffa_mem_region_attributes) *
			   memory_region->ep_count;
	constituents_offset =
		ffa_composite_constituent_offset(memory_region, 0);
	if (memory_region->ep_mem_access[0].composite_off <
		    sizeof(struct ffa_mem_region) + receivers_length ||
	    constituents_offset > fragment_length) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	composite = ffa_memory_region_get_composite(memory_region, 0);

	/*
	 * Ensure the number of constituents are within the memory bounds.
	 */
	constituents_length = sizeof(struct ffa_mem_region_addr_range) *
			      composite->addr_range_cnt;
	if (memory_share_length != constituents_offset + constituents_length)
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	if (fragment_length < memory_share_length &&
	    fragment_length < MAILBOX_SIZE) {
		pr_warn("Initial fragment length %d smaller than mailbox size.",
			fragment_length);
	}

	/*
	 * Clear is not allowed for memory sharing, as the sender still has
	 * access to the memory.
	 */
	if ((memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR) &&
	    share_func == FFA_MEM_SHARE) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	/* No other flags are allowed/supported here. */
	if (memory_region->flags & ~FFA_MEMORY_REGION_FLAG_CLEAR)
		return ffa_error(FFA_RET_INVALID_PARAMETERS);

	/* Check that the permissions are valid. */
	*permissions = memory_region->ep_mem_access[0].attrs;
	data_access = ffa_get_data_access_attr(*permissions);
	instruction_access = ffa_get_instruction_access_attr(*permissions);
	if (data_access == FFA_DATA_ACCESS_RESERVED ||
	    instruction_access == FFA_INSTRUCTION_ACCESS_RESERVED) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}
	if (instruction_access != FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED)
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	if (share_func == FFA_MEM_SHARE) {
		if (data_access == FFA_DATA_ACCESS_NOT_SPECIFIED)
			return ffa_error(FFA_RET_INVALID_PARAMETERS);
		/*
		 * According to section 6.11.3 of the FF-A spec NX is required
		 * for share operations (but must not be specified by the
		 * sender) so set it in the copy that we store, ready to be
		 * returned to the retriever.
		 */
		ffa_set_instruction_access_attr(permissions,
						FFA_INSTRUCTION_ACCESS_NX);
		memory_region->ep_mem_access[0].attrs = *permissions;
	}
	if (share_func == FFA_MEM_LEND &&
	    data_access == FFA_DATA_ACCESS_NOT_SPECIFIED) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}
	if (share_func == FFA_MEM_DONATE &&
	    data_access != FFA_DATA_ACCESS_NOT_SPECIFIED) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	return (struct arm_smccc_1_2_regs){ .a0 = FFA_SUCCESS };
}

/**
 * memory_send_tee_forward() - Forwards a memory send message on to the TEE.
 * @sender_vm_id: The FF-A ID of the sender.
 * @share_func:
 *   The FF-A function used for sharing the memory. Should be one of
 *   FFA_MEM_DONATE, FFA_MEM_LEND or FFA_MEM_SHARE.
 * @memory_region: The first fragment of the memory region descriptor.
 * @memory_share_length: The length of the entire memory region descriptor.
 * @fragment_length:
 *   The length of the first fragment of the memory region descriptor.
 *
 * Context: The TEE lock must be held while calling this function.
 *
 * Return: The result returned by the SPMD in EL3.
 */
static struct arm_smccc_1_2_regs
memory_send_tee_forward(ffa_vm_id_t sender_vm_id, uint32_t share_func,
			struct ffa_mem_region *memory_region,
			uint32_t memory_share_length, uint32_t fragment_length)
{
	struct arm_smccc_1_2_regs args =
		(struct arm_smccc_1_2_regs){ .a0 = share_func,
					     .a1 = memory_share_length,
					     .a2 = fragment_length };
	struct arm_smccc_1_2_regs ret;

	memcpy(spmd_rx_buffer, memory_region, fragment_length);
	arm_smccc_1_2_smc(&args, &ret);

	return ret;
}

/**
 * ffa_memory_send_continue_validate() - Gets the share state for continuing an
 *                                       operation to donate, lend or share
 *                                       memory, and checks that it is a valid
 *                                       request.
 * @share_states: A locked reference to the share states.
 * @handle: The memory region handle for the operation.
 * @share_state_ret: A pointer to initialise to the share state if it is found.
 * @from_vm_id: The FF-A ID of the sender.
 * @page_pool:
 *   The page pool into which to put pages freed from the memory region
 *   descriptor, if the operation fails.
 *
 * Return: FFA_SUCCESS if the request was valid, or the relevant FFA_ERROR if
 * not.
 */
static struct arm_smccc_1_2_regs ffa_memory_send_continue_validate(
	struct share_states_locked share_states, ffa_memory_handle_t handle,
	struct ffa_memory_share_state **share_state_ret, ffa_vm_id_t from_vm_id,
	struct hyp_pool *page_pool)
{
	struct ffa_memory_share_state *share_state;
	struct ffa_mem_region *memory_region;

	BUG_ON(share_state_ret == NULL);

	/*
	 * Look up the share state by handle and make sure that the VM ID
	 * matches.
	 */
	if (!get_share_state(share_states, handle, &share_state)) {
		pr_warn("Invalid handle for memory send continuation.");
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}
	memory_region = share_state->memory_region;

	if (memory_region->sender_id != from_vm_id) {
		pr_warn("Invalid sender.");
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	if (share_state->sending_complete) {
		pr_warn("Sending of memory handle is already complete.");
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	if (share_state->fragment_count == MAX_FRAGMENTS) {
		/*
		 * Log a warning as this is a sign that MAX_FRAGMENTS should
		 * probably be increased.
		 */
		pr_warn("Too many fragments for memory share with handle.");
		/* Free share state, as it's not possible to complete it. */
		share_state_free(share_states, share_state, page_pool);
		return ffa_error(FFA_RET_NO_MEMORY);
	}

	*share_state_ret = share_state;

	return (struct arm_smccc_1_2_regs){ .a0 = FFA_SUCCESS };
}

/**
 * memory_send_continue_tee_forward() - Forwards a memory send continuation
 *                                      message on to the TEE.
 * @sender_vm_id: The FF-A ID of the sender.
 * @fragment: A fragment of a memory region descriptor.
 * @fragment_length:
 *   The length of this fragment of the memory region descriptor.
 * @handle: The handle assigned to the memory region.
 *
 * Context: The TEE lock must be held while calling this function.
 *
 * Return: The result returned by the SPMD in EL3.
 */
static struct arm_smccc_1_2_regs
memory_send_continue_tee_forward(ffa_vm_id_t sender_vm_id, void *fragment,
				 uint32_t fragment_length,
				 ffa_memory_handle_t handle)
{
	struct arm_smccc_1_2_regs args = { .a0 = FFA_MEM_FRAG_TX,
					   .a1 = (uint32_t)handle,
					   .a2 = (uint32_t)(handle >> 32),
					   .a3 = fragment_length,
					   .a4 = (uint64_t)sender_vm_id << 16 };
	struct arm_smccc_1_2_regs ret;

	memcpy(spmd_rx_buffer, fragment, fragment_length);
	arm_smccc_1_2_smc(&args, &ret);

	return ret;
}

/**
 * ffa_memory_tee_send() - Validates a call to donate, lend or share memory to
 *                         the TEE and then updates the stage-2 page tables.
 * @from_pgt: The page table of the sender, i.e. the host.
 * @memory_region: The first fragment of the memory region descriptor to send.
 * @memory_share_length: The length of the entire memory region descriptor.
 * @fragment_length:
 *   The length of the first fragment of the memory region descriptor.
 * @share_func:
 *   The FF-A function used for sharing the memory. Must be one of
 *   FFA_MEM_DONATE, FFA_MEM_LEND or FFA_MEM_SHARE.
 * @page_pool:
 *   The page pool in which to put pages freed from the memory region
 *   descriptor.
 *
 * Specifically, checks if the message length and number of memory region
 * constituents match, and if the transition is valid for the type of memory
 * sending operation.
 *
 * Assumes that the caller has already found and locked the sender VM and the
 * TEE VM, and copied the memory region descriptor from the sender's TX buffer
 * to a freshly allocated page from the hypervisor's internal pool. The caller
 * must also have validated that the receiver VM ID is valid.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 *
 * Return: FFA_SUCCESS with the memory region handle, or an appropriate
 * FFA_ERROR value.
 */
struct arm_smccc_1_2_regs
ffa_memory_tee_send(struct kvm_pgtable *from_pgt,
		    struct ffa_mem_region *memory_region,
		    uint32_t memory_share_length, uint32_t fragment_length,
		    uint32_t share_func, struct hyp_pool *page_pool)
{
	ffa_memory_access_permissions_t permissions;
	struct arm_smccc_1_2_regs ret;

	hyp_assert_lock_held(&host_kvm.lock);
	hyp_assert_lock_held(&spmd.lock);

	/*
	 * If there is an error validating the `memory_region` then we need to
	 * free it because we own it but we won't be storing it in a share state
	 * after all.
	 */
	ret = ffa_memory_send_validate(memory_region, memory_share_length,
				       fragment_length, share_func,
				       &permissions);
	if (ret.a0 != FFA_SUCCESS)
		goto out;

	if (fragment_length == memory_share_length) {
		/* No more fragments to come, everything fit in one message. */
		struct ffa_composite_mem_region *composite =
			ffa_memory_region_get_composite(memory_region, 0);
		struct ffa_mem_region_addr_range *constituents =
			composite->constituents;
		enum kvm_pgtable_prot orig_from_mode;

		ret = ffa_send_check_update(
			from_pgt, &constituents, &composite->addr_range_cnt, 1,
			share_func, permissions,
			memory_region->flags & FFA_MEMORY_REGION_FLAG_CLEAR,
			&orig_from_mode);
		if (ret.a0 != FFA_SUCCESS)
			goto out;

		/* Forward memory send message on to TEE. */
		ret = memory_send_tee_forward(HOST_VM_ID, share_func,
					      memory_region,
					      memory_share_length,
					      fragment_length);

		if (ret.a0 != FFA_SUCCESS) {
			pr_warn("TEE didn't successfully complete memory send "
				"operation. Rolling back.");

			/*
			 * The TEE failed to complete the send operation, so roll back the page
			 * table update for the VM.
			 */
			BUG_ON(!ffa_region_group_identity_map(
				from_pgt, &constituents,
				&composite->addr_range_cnt, 1, orig_from_mode));
		}
	} else {
		struct share_states_locked share_states = share_states_lock();
		ffa_memory_handle_t handle;

		/*
		 * We need to wait for the rest of the fragments before we can
		 * check whether the transaction is valid and unmap the memory.
		 * Call the TEE so it can do its initial validation and assign a
		 * handle, and allocate a share state to keep what we have so
		 * far.
		 */
		ret = memory_send_tee_forward(HOST_VM_ID, share_func,
					      memory_region,
					      memory_share_length,
					      fragment_length);
		if (ret.a0 == FFA_ERROR) {
			goto out_unlock;
		} else if (ret.a0 != FFA_MEM_FRAG_RX) {
			pr_warn("Got unexpected response from TEE, expected "
				"FFA_MEM_FRAG_RX.");
			ret = ffa_error(FFA_RET_INVALID_PARAMETERS);
			goto out_unlock;
		}
		handle = ffa_frag_handle(ret);
		if (ret.a3 != fragment_length) {
			pr_warn("Got unexpected fragment offset for "
				"FFA_MEM_FRAG_RX from TEE.");
			ret = ffa_error(FFA_RET_INVALID_PARAMETERS);
			goto out_unlock;
		}
		if (ffa_frag_sender(ret) != HOST_VM_ID) {
			pr_warn("Got unexpected sender ID for "
				"FFA_MEM_FRAG_RX from TEE.");
			ret = ffa_error(FFA_RET_INVALID_PARAMETERS);
			goto out_unlock;
		}

		if (!allocate_share_state(share_states, share_func,
					  memory_region, fragment_length,
					  handle, NULL)) {
			pr_warn("Failed to allocate share state.");
			ret = ffa_error(FFA_RET_NO_MEMORY);
			goto out_unlock;
		}
		/*
		 * Don't free the memory region fragment, as it has been stored
		 * in the share state.
		 */
		memory_region = NULL;
	out_unlock:
		share_states_unlock(&share_states);
	}

out:
	if (memory_region != NULL) {
		/* Free memory_region. */
		hyp_put_page(page_pool, memory_region);
	}

	return ret;
}

/**
 * ffa_memory_tee_send_continue() - Continues an operation to donate, lend or
 *                                  share memory to the TEE VM.
 * @from_pgt: The page table of the sender, i.e. the host.
 * @fragment: A fragment of a memory region descriptor.
 * @fragment_length:
 *   The length of this fragment of the memory region descriptor.
 * @handle: The handle assigned to the memory region.
 * @page_pool:
 *   The page pool in which to put pages freed from the memory region
 *   descriptor.
 *
 * If this is the last fragment then checks that the transition is valid for the
 * type of memory sending operation and updates the stage-2 page tables of the
 * sender.
 *
 * Assumes that the caller has already found and locked the sender VM and copied
 * the memory region descriptor from the sender's TX buffer to a freshly
 * allocated page from the hypervisor's internal pool.
 *
 * This function takes ownership of the `memory_region` passed in and will free
 * it when necessary; it must not be freed by the caller.
 *
 * Return:
 *  * ``FFA_SUCCESS`` if this was the last fragment and the memory send
 *    operation has completed successfully.
 *  * ``FFA_MEM_FRAG_RX`` with the handle and next fragment offset if there are
 *    more fragments to come.
 *  * ``FFA_ERROR`` with an appropriate error code if the memory send operation
 *    failed.
 */
struct arm_smccc_1_2_regs ffa_memory_tee_send_continue(
	struct kvm_pgtable *from_pgt, void *fragment, uint32_t fragment_length,
	ffa_memory_handle_t handle, struct hyp_pool *page_pool)
{
	struct share_states_locked share_states = share_states_lock();
	struct ffa_memory_share_state *share_state;
	struct arm_smccc_1_2_regs ret;
	struct ffa_mem_region *memory_region;

	hyp_assert_lock_held(&host_kvm.lock);
	hyp_assert_lock_held(&spmd.lock);

	ret = ffa_memory_send_continue_validate(
		share_states, handle, &share_state, HOST_VM_ID, page_pool);
	if (ret.a0 != FFA_SUCCESS)
		goto out_free_fragment;
	memory_region = share_state->memory_region;

	if (memory_region->ep_mem_access[0].receiver != TEE_VM_ID) {
		pr_err("Got SPM-allocated handle for memory send to non-TEE "
		       "VM. This should never happen, and indicates a bug.");
		ret = ffa_error(FFA_RET_INVALID_PARAMETERS);
		goto out_free_fragment;
	}

	/* Add this fragment. */
	share_state->fragments[share_state->fragment_count] = fragment;
	share_state->fragment_constituent_counts[share_state->fragment_count] =
		fragment_length / sizeof(struct ffa_mem_region_addr_range);
	share_state->fragment_count++;

	/* Check whether the memory send operation is now ready to complete. */
	if (share_state_sending_complete(share_states, share_state)) {
		enum kvm_pgtable_prot orig_from_mode;

		ret = ffa_memory_send_complete(from_pgt, share_states,
					       share_state, page_pool,
					       &orig_from_mode);

		if (ret.a0 == FFA_SUCCESS) {
			/*
			 * Forward final fragment on to the TEE so that
			 * it can complete the memory sending operation.
			 */
			ret = memory_send_continue_tee_forward(
				HOST_VM_ID, fragment, fragment_length, handle);

			if (ret.a0 != FFA_SUCCESS) {
				/*
				 * The error will be passed on to the caller,
				 * but log it here too.
				 */
				pr_warn("TEE didn't successfully complete "
					"memory send operation. Rolling back.");

				/*
				 * The TEE failed to complete the send
				 * operation, so roll back the page table update
				 * for the VM.
				 */
				BUG_ON(!ffa_region_group_identity_map(
					from_pgt, share_state->fragments,
					share_state->fragment_constituent_counts,
					share_state->fragment_count,
					orig_from_mode));
			}

			/* Free share state. */
			share_state_free(share_states, share_state, page_pool);
		} else {
			/* Abort sending to TEE. */
			struct arm_smccc_1_2_regs tee_ret;
			struct arm_smccc_1_2_regs args = {
				.a0 = FFA_MEM_RECLAIM,
				.a1 = (uint32_t)handle,
				.a2 = (uint32_t)(handle >> 32)
			};
			arm_smccc_1_2_smc(&args, &tee_ret);

			if (tee_ret.a0 != FFA_SUCCESS) {
				/*
				 * Nothing we can do if TEE doesn't abort
				 * properly, just log it.
				 */
				pr_warn("TEE didn't successfully abort failed "
					"memory send operation.");
			}
			/*
			 * We don't need to free the share state in this case
			 * because ffa_memory_send_complete does that already.
			 */
		}
	} else {
		uint32_t next_fragment_offset =
			share_state_next_fragment_offset(share_states,
							 share_state);

		ret = memory_send_continue_tee_forward(HOST_VM_ID, fragment,
						       fragment_length, handle);

		if (ret.a0 != FFA_MEM_FRAG_RX ||
		    ffa_frag_handle(ret) != handle ||
		    ret.a3 != next_fragment_offset ||
		    ffa_frag_sender(ret) != HOST_VM_ID) {
			pr_warn("Got unexpected result from forwarding "
				"FFA_MEM_FRAG_TX to TEE");
			/* Free share state. */
			share_state_free(share_states, share_state, page_pool);
			ret = ffa_error(FFA_RET_INVALID_PARAMETERS);
			goto out;
		}

		ret = (struct arm_smccc_1_2_regs){ .a0 = FFA_MEM_FRAG_RX,
						   .a1 = (uint32_t)handle,
						   .a2 = (uint32_t)(handle >>
								    32),
						   .a3 = next_fragment_offset };
	}
	goto out;

out_free_fragment:
	hyp_put_page(page_pool, fragment);

out:
	share_states_unlock(&share_states);
	return ret;
}
