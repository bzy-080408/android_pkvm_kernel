// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 *
 * Kernel module for testing FF-A on aarch64, possibly via the pKVM FF-A implementation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/align.h>
#include <linux/arm_ffa.h>
#include <linux/arm-smccc.h>
#include <linux/kvm_types.h>
#include "../tools/testing/selftests/kselftest_module.h"

/** FF-A version 1.0. */
#define FFA_VERSION_1_0 (1 << 16 | 0)

#define MAILBOX_SIZE 4096

#define HOST_VM_ID 0x0001
#define TEE_VM_ID 0x8000

/** The ID of a VM. These are assigned sequentially starting with an offset. */
typedef uint16_t ffa_vm_id_t;

/**
 * A globally-unique ID assigned by the hypervisor for a region of memory being
 * sent between VMs.
 */
typedef uint64_t ffa_memory_handle_t;

#define FFA_MEMORY_HANDLE_ALLOCATOR_MASK                                       \
	((ffa_memory_handle_t)0x8000000000000000)
#define FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR                                 \
	((ffa_memory_handle_t)0x8000000000000000)
#define FFA_MEMORY_HANDLE_INVALID ((ffa_memory_handle_t)0xffffffffffffffff)

static inline ffa_memory_handle_t ffa_assemble_handle(uint32_t a1, uint32_t a2)
{
	return (uint64_t)a1 | (uint64_t)a2 << 32;
}

static inline ffa_memory_handle_t
ffa_mem_success_handle(struct arm_smccc_1_2_regs args)
{
	return ffa_assemble_handle(args.a2, args.a3);
}

static inline ffa_memory_handle_t
ffa_frag_handle(struct arm_smccc_1_2_regs args)
{
	return ffa_assemble_handle(args.a1, args.a2);
}

KSTM_MODULE_GLOBALS();

static void *tx_buffer;
static void *rx_buffer;

static inline struct arm_smccc_1_2_regs ffa_mem_share(uint32_t length,
						      uint32_t fragment_length)
{
	struct arm_smccc_1_2_regs args = (struct arm_smccc_1_2_regs){
		.a0 = FFA_MEM_SHARE, .a1 = length, .a2 = fragment_length
	};
	struct arm_smccc_1_2_regs ret;

	arm_smccc_1_2_smc(&args, &ret);

	return ret;
}

static inline struct arm_smccc_1_2_regs
ffa_mem_frag_tx(ffa_memory_handle_t handle, uint32_t fragment_length)
{
	struct arm_smccc_1_2_regs args =
		(struct arm_smccc_1_2_regs){ .a0 = FFA_MEM_FRAG_TX,
					     .a1 = (uint32_t)handle,
					     .a2 = (uint32_t)(handle >> 32),
					     .a3 = fragment_length };
	struct arm_smccc_1_2_regs ret;

	arm_smccc_1_2_smc(&args, &ret);

	return ret;
}

static void print_error(struct arm_smccc_1_2_regs ret)
{
	if (ret.a0 == FFA_ERROR) {
		switch (ret.a2) {
		case FFA_RET_NOT_SUPPORTED:
			pr_err("Got FFA_ERROR NOT_SUPPORTED");
			break;
		case FFA_RET_INVALID_PARAMETERS:
			pr_err("Got FFA_ERROR INVALID_PARAMETERS");
			break;
		case FFA_RET_NO_MEMORY:
			pr_err("Got FFA_ERROR NO_MEMORY");
			break;
		case FFA_RET_BUSY:
			pr_err("Got FFA_ERROR BUSY");
			break;
		case FFA_RET_INTERRUPTED:
			pr_err("Got FFA_ERROR INTERRUPTED");
			break;
		case FFA_RET_DENIED:
			pr_err("Got FFA_ERROR DENIED");
			break;
		case FFA_RET_RETRY:
			pr_err("Got FFA_ERROR RETRY");
			break;
		case FFA_RET_ABORTED:
			pr_err("Got FFA_ERROR ABORTED");
			break;
		default:
			pr_err("Got FFA_ERROR with unrecognised error code %#x",
			       ret.a2);
			break;
		}
	} else {
		pr_err("Got unexpected FF-A function %#x", ret.a0);
	}
}

/**
 * Gets the `ffa_composite_memory_region` for the given receiver from an
 * `ffa_memory_region`, or NULL if it is not valid.
 */
static inline struct ffa_composite_mem_region *
ffa_memory_region_get_composite(struct ffa_mem_region *memory_region,
				uint32_t receiver_index)
{
	uint32_t offset =
		memory_region->ep_mem_access[receiver_index].composite_off;

	if (offset == 0)
		return NULL;

	return (struct ffa_composite_mem_region *)((uint8_t *)memory_region +
						   offset);
}

/**
 * Initialises the header of the given `ffa_memory_region`, not including the
 * composite memory region offset.
 */
static void ffa_memory_region_init_header(struct ffa_mem_region *memory_region,
					  ffa_vm_id_t sender,
					  uint8_t attributes, uint32_t flags,
					  ffa_memory_handle_t handle,
					  uint32_t tag, ffa_vm_id_t receiver,
					  uint8_t permissions)
{
	memory_region->sender_id = sender;
	memory_region->attributes = attributes;
	memory_region->reserved_0 = 0;
	memory_region->flags = flags;
	memory_region->handle = handle;
	memory_region->tag = tag;
	memory_region->reserved_1 = 0;
	memory_region->ep_count = 1;
	memory_region->ep_mem_access[0].receiver = receiver;
	memory_region->ep_mem_access[0].attrs = permissions;
	memory_region->ep_mem_access[0].flag = 0;
	memory_region->ep_mem_access[0].reserved = 0;
}

/**
 * Initialises the given `ffa_memory_region` and copies as many as possible of
 * the given constituents to it.
 *
 * Returns the number of constituents remaining which wouldn't fit, and (via
 * return parameters) the size in bytes of the first fragment of data copied to
 * `memory_region` (attributes, constituents and memory region header size), and
 * the total size of the memory sharing message including all constituents.
 */
static uint32_t
ffa_memory_region_init(struct ffa_mem_region *memory_region,
		       size_t memory_region_max_size, ffa_vm_id_t sender,
		       ffa_vm_id_t receiver,
		       const struct ffa_mem_region_addr_range constituents[],
		       uint32_t constituent_count, uint32_t tag, uint32_t flags,
		       uint8_t data_access, uint8_t instruction_access,
		       uint8_t type, uint8_t cacheability, uint8_t shareability,
		       uint32_t *total_length, uint32_t *fragment_length)
{
	/* The memory region's permissions. */
	uint8_t permissions = data_access | instruction_access;
	/* Set memory region's page attributes. */
	uint8_t attributes = type | cacheability | shareability;
	struct ffa_composite_mem_region *composite_memory_region;
	uint32_t fragment_max_constituents;
	uint32_t count_to_copy;
	uint32_t i;
	uint32_t constituents_offset;

	ffa_memory_region_init_header(memory_region, sender, attributes, flags,
				      0, tag, receiver, permissions);
	/*
	 * Note that `sizeof(struct ffa_mem_region)` and `sizeof(struct
	 * ffa_mem_region_attributes)` must both be multiples of 16 (as verified by the
	 * asserts in `ffa_memory.c`, so it is guaranteed that the offset we
	 * calculate here is aligned to a 64-bit boundary and so 64-bit values
	 * can be copied without alignment faults.
	 */
	memory_region->ep_mem_access[0].composite_off =
		sizeof(struct ffa_mem_region) +
		memory_region->ep_count *
			sizeof(struct ffa_mem_region_attributes);

	composite_memory_region =
		ffa_memory_region_get_composite(memory_region, 0);
	composite_memory_region->total_pg_cnt = 0;
	composite_memory_region->addr_range_cnt = constituent_count;
	composite_memory_region->reserved = 0;

	constituents_offset = memory_region->ep_mem_access[0].composite_off +
			      sizeof(struct ffa_composite_mem_region);
	fragment_max_constituents =
		(memory_region_max_size - constituents_offset) /
		sizeof(struct ffa_mem_region_addr_range);

	count_to_copy = constituent_count;
	if (count_to_copy > fragment_max_constituents)
		count_to_copy = fragment_max_constituents;

	for (i = 0; i < constituent_count; ++i) {
		if (i < count_to_copy) {
			composite_memory_region->constituents[i] =
				constituents[i];
		}
		composite_memory_region->total_pg_cnt += constituents[i].pg_cnt;
	}

	if (total_length != NULL) {
		*total_length =
			constituents_offset +
			composite_memory_region->addr_range_cnt *
				sizeof(struct ffa_mem_region_addr_range);
	}
	if (fragment_length != NULL) {
		*fragment_length =
			constituents_offset +
			count_to_copy *
				sizeof(struct ffa_mem_region_addr_range);
	}

	return composite_memory_region->addr_range_cnt - count_to_copy;
}

static uint32_t
ffa_memory_fragment_init(struct ffa_mem_region_addr_range *fragment,
			 size_t fragment_max_size,
			 const struct ffa_mem_region_addr_range constituents[],
			 uint32_t constituent_count, uint32_t *fragment_length)
{
	uint32_t fragment_max_constituents =
		fragment_max_size / sizeof(struct ffa_mem_region_addr_range);
	uint32_t count_to_copy = constituent_count;
	uint32_t i;

	if (count_to_copy > fragment_max_constituents)
		count_to_copy = fragment_max_constituents;

	for (i = 0; i < count_to_copy; ++i)
		fragment[i] = constituents[i];

	if (fragment_length != NULL) {
		*fragment_length = count_to_copy *
				   sizeof(struct ffa_mem_region_addr_range);
	}

	return constituent_count - count_to_copy;
}

/** Calling an unsupported FF-A function should result in an error. */
static int __init test_invalid_smc(void)
{
	struct arm_smccc_1_2_regs ret;
	const struct arm_smccc_1_2_regs args = { .a0 = FFA_MEM_OP_PAUSE };

	arm_smccc_1_2_smc(&args, &ret);

	if (ret.a0 != FFA_ERROR && ret.a2 == FFA_RET_NOT_SUPPORTED) {
		pr_err("FFA_MEM_OP_PAUSE: expected FFA_ERROR NOT_SUPPORTED");
		print_error(ret);
		return -1;
	}

	return 0;
}

static int __init test_get_version(void)
{
	struct arm_smccc_1_2_regs ret;
	const struct arm_smccc_1_2_regs args = { .a0 = FFA_VERSION,
						 .a1 = FFA_VERSION_1_0 };

	arm_smccc_1_2_smc(&args, &ret);

	if (ret.a0 != FFA_VERSION_1_0) {
		pr_err("FFA_VERSION: expected %#x but got %#x", FFA_VERSION_1_0,
		       ret.a0);
		return -1;
	}

	return 0;
}

static int set_up_mailbox(void)
{
	struct arm_smccc_1_2_regs ret;
	const hpa_t tx_address = virt_to_phys(tx_buffer);
	const hpa_t rx_address = virt_to_phys(rx_buffer);
	const struct arm_smccc_1_2_regs args = { .a0 = FFA_FN64_RXTX_MAP,
						 .a1 = tx_address,
						 .a2 = rx_address,
						 .a3 = 1 };

	pr_err("TX buffer virt %#zx, phys %#zx", tx_buffer, tx_address);
	arm_smccc_1_2_smc(&args, &ret);

	if (ret.a0 != FFA_SUCCESS) {
		pr_err("FFA_RXTX_MAP: expected FFA_SUCCESS");
		print_error(ret);
		return -1;
	}

	return 0;
}

static int __init test_rxtx_map(void)
{
	if (set_up_mailbox() != 0)
		return -1;

	return 0;
}

static ffa_memory_handle_t
init_and_send(struct ffa_mem_region_addr_range constituents[],
	      size_t constituents_count)
{
	uint32_t total_length;
	uint32_t fragment_length;
	struct arm_smccc_1_2_regs ret;
	ffa_memory_handle_t handle;

	if (ffa_memory_region_init(tx_buffer, MAILBOX_SIZE, HOST_VM_ID,
				   TEE_VM_ID, constituents, constituents_count,
				   0, 0, FFA_MEM_RW, 0, FFA_MEM_NORMAL,
				   FFA_MEM_WRITE_BACK, FFA_MEM_INNER_SHAREABLE,
				   &total_length, &fragment_length) != 0) {
		pr_err("Failed to initialise memory region");
		return FFA_MEMORY_HANDLE_INVALID;
	}
	if (total_length != fragment_length) {
		pr_err("total_length doesn't match fragment length");
		return FFA_MEMORY_HANDLE_INVALID;
	}
	ret = ffa_mem_share(total_length, fragment_length);
	if (ret.a0 != FFA_SUCCESS) {
		pr_err("FFA_MEM_SHARE failed");
		print_error(ret);
		return FFA_MEMORY_HANDLE_INVALID;
	}
	handle = ffa_mem_success_handle(ret);
	if (handle == 0 || (handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
				   FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR) {
		pr_err("Invalid FFA_MEM_SHARE returned invalid handle %#lx on success.",
		       handle);
		return FFA_MEMORY_HANDLE_INVALID;
	}

	return handle;
}

/**
 * Memory can be shared to a TEE in the secure world via the Trusty SPD in TF-A. (The TEE itself
 * never actually retrieves it in these tests, we're just testing the FF-A interface between pKVM
 * and the Trusty SPD.)
 */
static int __init test_memory_share(void)
{
	uint8_t *page = (uint8_t *)get_zeroed_page(GFP_ATOMIC);
	const hpa_t address = virt_to_phys(page);
	struct ffa_mem_region_addr_range constituents[] = {
		{ .address = address, .pg_cnt = 1 },
	};
	int i;

	if (page == NULL) {
		pr_err("Failed to allocate page to share");
		return -1;
	}

	/* Dirty the memory before sharing it. */
	memset(page, 'b', FFA_PAGE_SIZE);

	if (init_and_send(constituents, ARRAY_SIZE(constituents)) ==
	    FFA_MEMORY_HANDLE_INVALID) {
		return -1;
	}

	/* Make sure we can still write to it. */
	for (i = 0; i < FFA_PAGE_SIZE; ++i)
		page[i] = i;

	/* Leak the shared page, so it doesn't get reused for something else. */

	return 0;
}

/**
 * Memory can be shared to Trusty SPD in multiple fragments.
 */
static int __init test_memory_share_fragmented(void)
{
	uint8_t *page0 = (uint8_t *)get_zeroed_page(GFP_ATOMIC);
	uint8_t *page1 = (uint8_t *)get_zeroed_page(GFP_ATOMIC);
	const hpa_t address0 = virt_to_phys(page0);
	const hpa_t address1 = virt_to_phys(page1);
	struct ffa_mem_region_addr_range constituents[] = {
		{ .address = address0, .pg_cnt = 1 },
		{ .address = address1, .pg_cnt = 1 },
	};
	int i;
	ffa_memory_handle_t handle;
	uint32_t total_length;
	uint32_t fragment_length;
	struct arm_smccc_1_2_regs ret;

	if (page0 == NULL || page1 == NULL) {
		pr_err("Failed to allocate pages to share");
		return -1;
	}

	/* Dirty the memory before sharing it. */
	memset(page0, 'b', FFA_PAGE_SIZE);
	memset(page1, 'b', FFA_PAGE_SIZE);

	if (ffa_memory_region_init(
		    tx_buffer, MAILBOX_SIZE, HOST_VM_ID, TEE_VM_ID,
		    constituents, ARRAY_SIZE(constituents), 0, 0, FFA_MEM_RW, 0,
		    FFA_MEM_NORMAL, FFA_MEM_WRITE_BACK, FFA_MEM_INNER_SHAREABLE,
		    &total_length, &fragment_length) != 0) {
		pr_err("Failed to initialise memory region");
		return -1;
	}
	/* Send the first fragment without the last constituent. */
	fragment_length -= sizeof(struct ffa_mem_region_addr_range);
	ret = ffa_mem_share(total_length, fragment_length);
	if (ret.a0 != FFA_MEM_FRAG_RX || ret.a3 != fragment_length) {
		pr_err("Failed to send first fragment.");
		return -1;
	}
	handle = ffa_frag_handle(ret);

	/* Send second fragment. */
	if (ffa_memory_fragment_init(tx_buffer, MAILBOX_SIZE, constituents + 1,
				     1, &fragment_length) != 0) {
		return -1;
	}
	ret = ffa_mem_frag_tx(handle, fragment_length);
	if (ret.a0 != FFA_SUCCESS || ffa_mem_success_handle(ret) != handle) {
		pr_err("Failed to send second fragment.");
		return -1;
	}
	pr_info("Got handle %#x.", handle);
	if (handle == 0 || (handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
				   FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR) {
		return -1;
	}

	/* Make sure we can still write to it. */
	for (i = 0; i < FFA_PAGE_SIZE; ++i) {
		page0[i] = i;
		page1[i] = i;
	}

	/* Leak the shared pages, so they don't get reused for something else. */

	return 0;
}

static void __init selftest(void)
{
	tx_buffer = (void *)get_zeroed_page(GFP_ATOMIC);
	if (tx_buffer == NULL)
		pr_err("Failed to allocate TX buffer");
	rx_buffer = (void *)get_zeroed_page(GFP_ATOMIC);
	if (rx_buffer == NULL)
		pr_err("Failed to allocate RX buffer");

	pr_info("test_invalid_smc");
	KSTM_CHECK_ZERO(test_invalid_smc());
	pr_info("test_get_version");
	KSTM_CHECK_ZERO(test_get_version());
	pr_info("test_rxtx_map");
	KSTM_CHECK_ZERO(test_rxtx_map());
	pr_info("test_memory_share");
	KSTM_CHECK_ZERO(test_memory_share());
	pr_info("test_memory_share_fragmented");
	KSTM_CHECK_ZERO(test_memory_share_fragmented());
}

KSTM_MODULE_LOADERS(test_ffa);
MODULE_AUTHOR("Andrew Walbran <qwandor@google.com>");
MODULE_LICENSE("GPL");
