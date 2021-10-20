/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#define FFA_MIN_FUNC_NUM 0x60
#define FFA_MAX_FUNC_NUM 0x7F

/** FF-A 1.0 version number. */
#define FFA_SUPPORTED_VERSION (1 << 16 | 0)

/**
 * typedef ffa_vm_id_t - The ID of a VM.
 *
 * These are assigned sequentially starting with an offset.
 */
typedef u16 ffa_vm_id_t;

/**
 * typedef ffa_memory_handle_t - A globally-unique ID assigned by the hypervisor
 *                               for a region of memory being sent between
 *                               partitions.
 */
typedef u64 ffa_memory_handle_t;

#define FFA_MEMORY_HANDLE_ALLOCATOR_MASK                                       \
	((ffa_memory_handle_t)0x8000000000000000)
#define FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR                                 \
	((ffa_memory_handle_t)0x8000000000000000)
#define FFA_MEMORY_HANDLE_INVALID ((ffa_memory_handle_t)0xffffffffffffffff)

/**
 * typedef ffa_vm_id_t - A count of VMs.
 *
 * This has the same range as the VM IDs but we give it a different name to make
 * the different semantics clear.
 */
typedef ffa_vm_id_t ffa_vm_count_t;

/** typedef ffa_vcpu_index_t - The index of a vCPU within a particular VM. */
typedef u16 ffa_vcpu_index_t;

/**
 * typedef ffa_vcpu_index_t - A count of vCPUs.
 *
 * This has the same range as the vCPU indices but we give it a different name
 * to make the different semantics clear.
 */
typedef ffa_vcpu_index_t ffa_vcpu_count_t;

enum ffa_data_access {
	FFA_DATA_ACCESS_NOT_SPECIFIED,
	FFA_DATA_ACCESS_RO,
	FFA_DATA_ACCESS_RW,
	FFA_DATA_ACCESS_RESERVED,
};

enum ffa_instruction_access {
	FFA_INSTRUCTION_ACCESS_NOT_SPECIFIED,
	FFA_INSTRUCTION_ACCESS_NX,
	FFA_INSTRUCTION_ACCESS_X,
	FFA_INSTRUCTION_ACCESS_RESERVED,
};

typedef u8 ffa_memory_access_permissions_t;

/**
 * typedef ffa_memory_attributes_t - Attributes of a memory range.
 *
 * This corresponds to table 44 of the FF-A 1.0 EAC specification, "Memory
 * region attributes descriptor".
 */
typedef u8 ffa_memory_attributes_t;

#define FFA_DATA_ACCESS_OFFSET (0x0U)
#define FFA_DATA_ACCESS_MASK ((0x3U) << FFA_DATA_ACCESS_OFFSET)

#define FFA_INSTRUCTION_ACCESS_OFFSET (0x2U)
#define FFA_INSTRUCTION_ACCESS_MASK ((0x3U) << FFA_INSTRUCTION_ACCESS_OFFSET)

#define FFA_MEMORY_TYPE_OFFSET (0x4U)
#define FFA_MEMORY_TYPE_MASK ((0x3U) << FFA_MEMORY_TYPE_OFFSET)

#define FFA_MEMORY_CACHEABILITY_OFFSET (0x2U)
#define FFA_MEMORY_CACHEABILITY_MASK ((0x3U) << FFA_MEMORY_CACHEABILITY_OFFSET)

#define FFA_MEMORY_SHAREABILITY_OFFSET (0x0U)
#define FFA_MEMORY_SHAREABILITY_MASK ((0x3U) << FFA_MEMORY_SHAREABILITY_OFFSET)

#define ATTR_FUNCTION_SET(name, container_type, offset, mask)                  \
	static inline void ffa_set_##name##_attr(container_type *attr,         \
						 const enum ffa_##name perm)   \
	{                                                                      \
		*attr = (*attr & ~(mask)) | ((perm << offset) & mask);         \
	}

#define ATTR_FUNCTION_GET(name, container_type, offset, mask)                  \
	static inline enum ffa_##name ffa_get_##name##_attr(                   \
		container_type attr)                                           \
	{                                                                      \
		return (enum ffa_##name)((attr & mask) >> offset);             \
	}

ATTR_FUNCTION_SET(data_access, ffa_memory_access_permissions_t,
		  FFA_DATA_ACCESS_OFFSET, FFA_DATA_ACCESS_MASK)
ATTR_FUNCTION_GET(data_access, ffa_memory_access_permissions_t,
		  FFA_DATA_ACCESS_OFFSET, FFA_DATA_ACCESS_MASK)

ATTR_FUNCTION_SET(instruction_access, ffa_memory_access_permissions_t,
		  FFA_INSTRUCTION_ACCESS_OFFSET, FFA_INSTRUCTION_ACCESS_MASK)
ATTR_FUNCTION_GET(instruction_access, ffa_memory_access_permissions_t,
		  FFA_INSTRUCTION_ACCESS_OFFSET, FFA_INSTRUCTION_ACCESS_MASK)

/**
 * typedef ffa_memory_receiver_flags_t - Flags to indicate properties of
 *                                       receivers during memory region
 *                                       retrieval.
 */
typedef uint8_t ffa_memory_receiver_flags_t;

/** Flags to control the behaviour of a memory sharing transaction. */
typedef u32 ffa_memory_region_flags_t;

/**
 * Clear memory region contents after unmapping it from the sender and before
 * mapping it for any receiver.
 */
#define FFA_MEMORY_REGION_FLAG_CLEAR 0x1

/**
 * Whether the hypervisor may time slice the memory sharing or retrieval
 * operation.
 */
#define FFA_MEMORY_REGION_FLAG_TIME_SLICE 0x2

/**
 * Whether the hypervisor should clear the memory region after the receiver
 * relinquishes it or is aborted.
 */
#define FFA_MEMORY_REGION_FLAG_CLEAR_RELINQUISH 0x4

/**
 * Descriptor used for FFA_MEM_RELINQUISH requests. This corresponds to table
 * 150 of the FF-A 1.0 EAC specification, "Descriptor to relinquish a memory
 * region".
 */
struct ffa_mem_relinquish {
	ffa_memory_handle_t handle;
	ffa_memory_region_flags_t flags;
	uint32_t endpoint_count;
	ffa_vm_id_t endpoints[];
};

/**
 * Gets the `ffa_composite_mem_region` for the given receiver from an
 * `ffa_mem_region`, or NULL if it is not valid.
 */
static inline struct ffa_composite_mem_region *
ffa_memory_region_get_composite(struct ffa_mem_region *memory_region,
				uint32_t receiver_index)
{
	uint32_t offset = memory_region->ep_mem_access[receiver_index]
				  .composite_off;

	if (offset == 0)
		return NULL;

	return (struct ffa_composite_mem_region *)((uint8_t *)memory_region +
						   offset);
}

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

static inline ffa_vm_id_t ffa_frag_sender(struct arm_smccc_1_2_regs args)
{
	return (args.a4 >> 16) & 0xffff;
}

static inline struct arm_smccc_1_2_regs
ffa_mem_success(ffa_memory_handle_t handle)
{
	return (struct arm_smccc_1_2_regs){ .a0 = FFA_SUCCESS,
					    .a2 = (uint32_t)handle,
					    .a3 = (uint32_t)(handle >> 32) };
}

// TODO: The rest of this file should probably be in a different file, as it's specific to our
// implementation rather than general FF-A types.

/**
 * ffa_error() - Constructs an FF-A error return value with the specified error
 *               code.
 * @error_code: A valid FF-A error code, i.e. one of the FFA_RET_* constants.
 *
 * Return: An FFA_ERROR value with the given code.
 */
static struct arm_smccc_1_2_regs ffa_error(u64 error_code)
{
	return (struct arm_smccc_1_2_regs){ .a0 = FFA_ERROR, .a2 = error_code };
}

/*
 * The size of RX/TX buffer which we support. The implementation assumes that
 * this is the same size as the stage 2 page table page size.
 */
// TODO: Support other page sizes before this goes upstream.
#define MAILBOX_SIZE 4096

#define HOST_VM_ID 0x0001
#define TEE_VM_ID 0x8000

extern uint8_t spmd_tx_buffer[MAILBOX_SIZE];
extern uint8_t spmd_rx_buffer[MAILBOX_SIZE];

void *hyp_map(phys_addr_t start, size_t length, enum kvm_pgtable_prot prot);
int hyp_unmap(phys_addr_t start, size_t length);
