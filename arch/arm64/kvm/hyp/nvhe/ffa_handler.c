// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include <asm/kvm_pgtable.h>
#include <asm/kvm_pkvm.h>
#include <linux/arm-smccc.h>
#include <linux/arm_ffa.h>
#include <linux/kvm_types.h>
#include <linux/printk.h>
#include <nvhe/ffa.h>
#include <nvhe/ffa_handler.h>
#include <nvhe/ffa_memory.h>
#include <nvhe/gfp.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/spinlock.h>
#include <nvhe/trap_handler.h>
#include <stdalign.h>

// TODO: Initialise this properly
u64 __ro_after_init smccc_has_sve_hint;

/* Mailboxes for communicating with the SPMD in EL3. */
__aligned(FFA_PAGE_SIZE) uint8_t spmd_tx_buffer[MAILBOX_SIZE];
__aligned(FFA_PAGE_SIZE) uint8_t spmd_rx_buffer[MAILBOX_SIZE];

static struct hyp_pool descriptor_pool;

struct spmd spmd;

static bool is_ffa_call(u64 func_id)
{
	return ARM_SMCCC_IS_FAST_CALL(func_id) &&
	       ARM_SMCCC_OWNER_NUM(func_id) == ARM_SMCCC_OWNER_STANDARD &&
	       ARM_SMCCC_FUNC_NUM(func_id) >= FFA_MIN_FUNC_NUM &&
	       ARM_SMCCC_FUNC_NUM(func_id) <= FFA_MAX_FUNC_NUM;
}

/**
 * ffa_version() - Handles the FFA_VERSION function.
 * @input_version: The version passed by the caller; not currently used.
 *
 * Return: The supported FF-A version, encoded appropriately.
 */
static struct arm_smccc_1_2_regs ffa_version(u32 input_version)
{
	return (struct arm_smccc_1_2_regs){
		.a0 = FFA_SUPPORTED_VERSION,
	};
}

/**
 * ffa_id_get() - Handles the FFA_ID_GET function.
 *
 * Return: FFA_SUCCESS with the FF-A partition ID of the host.
 */
static struct arm_smccc_1_2_regs ffa_id_get(void)
{
	return (struct arm_smccc_1_2_regs){
		.a0 = FFA_SUCCESS,
		.a2 = HOST_VM_ID,
	};
}

/**
 * ffa_init() - Initialises the FF-A module, by setting up buffers with the EL3
 * firmware and initialising the page pool.
 */
int ffa_init(void *descriptor_pool_base)
{
	unsigned long pfn;
	int pool_ret;
	struct arm_smccc_1_2_regs ret;
	phys_addr_t rx_pa = hyp_virt_to_phys(spmd_rx_buffer);
	phys_addr_t tx_pa = hyp_virt_to_phys(spmd_tx_buffer);
	/*
	 * TX and RX are swapped around because the RX buffer from the SPMD's point of view is
	 * equivalent to the TX buffer from a VM's point of view.
	 */
	const struct arm_smccc_1_2_regs args = { .a0 = FFA_FN64_RXTX_MAP,
						 .a1 = rx_pa,
						 .a2 = tx_pa,
						 .a3 = MAILBOX_SIZE /
						       FFA_PAGE_SIZE };

	pfn = hyp_virt_to_pfn(descriptor_pool_base);
	pool_ret =
		hyp_pool_init(&descriptor_pool, pfn, ffa_descriptor_pages(), 0);
	if (pool_ret != 0)
		return pool_ret;

	hyp_spin_lock_init(&spmd.lock);

	arm_smccc_1_2_smc(&args, &ret);

	if (ret.a0 == SMCCC_RET_NOT_SUPPORTED) {
		pr_warn("Unknown function setting up EL3 message buffers. "
			"Memory sharing with secure world will not work.");
	} else if (ret.a0 != FFA_SUCCESS) {
		pr_warn("Error or unexpected function returned setting up EL3 message buffers.");
		BUG();
	}

	return 0;
}

static struct arm_smccc_1_2_regs
ffa_mem_reclaim(ffa_memory_handle_t handle, ffa_memory_region_flags_t flags)
{
	struct arm_smccc_1_2_regs ret;

	if ((handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
	    FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR) {
		/* Sending memory to normal world VMs is not supported, so nor is reclaiming. */
		ret = ffa_error(FFA_RET_INVALID_PARAMETERS);
	} else {
		hyp_spin_lock(&host_kvm.lock);
		hyp_spin_lock(&spmd.lock);

		ret = ffa_memory_tee_reclaim(handle, flags);

		hyp_spin_unlock(&host_kvm.lock);
		hyp_spin_unlock(&spmd.lock);
	}

	return ret;
}

/**
 * ffa_mem_send() - Handles the FFA_MEM_DONATE, FFA_MEM_LEND and FFA_MEM_SHARE
 *                  functions.
 * @share_func: The function ID of the FF-A function used to send the memory.
 *              Should be one of FFA_MEM_DONATE, FFA_MEM_LEND or FFA_MEM_SHARE.
 * @length: The length of the entire memory region descriptor in bytes.
 * @fragment_length: The length of the first fragment of the memory region
 *                   descriptor.
 * @address: The address of the memory region descriptor, or 0 to use the TX
 *           mailbox. Non-zero values are not currently supported.
 * @page_count: The number of FFA_PAGE_SIZE pages used for the memory region
 *              descriptor, or 0 if the TX mailbox is being used. Non-zero
 *              values are not currently supported.
 *
 * Return: FFA_SUCCESS with the handle assigned to the memory region, or an
 *         appropriate FFA_ERROR.
 */
static struct arm_smccc_1_2_regs ffa_mem_send(u32 share_func, u32 length,
					      u32 fragment_length,
					      hpa_t address, u32 page_count)
{
	const void *from_msg;
	struct ffa_mem_region *memory_region;
	struct arm_smccc_1_2_regs ret;

	if (address != 0 || page_count != 0) {
		/* pKVM only supports passing the descriptor in the TX mailbox. */
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	if (fragment_length > length) {
		/* Fragment length greater than total length. */
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}
	if (fragment_length <
	    sizeof(struct ffa_mem_region) +
		    sizeof(struct ffa_mem_region_attributes)) {
		/* Initial fragment length smaller than header size. */
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	/* Lock host VM info to get TX buffer address. */
	hyp_spin_lock(&host_kvm.lock);
	from_msg = host_kvm.tx_buffer;
	hyp_spin_unlock(&host_kvm.lock);

	if (from_msg == NULL) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	/*
	 * Copy the memory region descriptor to a fresh page from the memory
	 * pool. This prevents the sender from changing it underneath us, and
	 * also lets us keep it around in the share state table if needed.
	 */
	if (fragment_length > MAILBOX_SIZE) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}
	// TODO: Do we need locking?
	memory_region = (struct ffa_mem_region *)hyp_alloc_pages(
		&descriptor_pool, get_order(MAILBOX_SIZE));
	if (memory_region == NULL) {
		return ffa_error(FFA_RET_NO_MEMORY);
	}
	memcpy(memory_region, from_msg, fragment_length);

	/* The sender must match the caller. */
	if (memory_region->sender_id != HOST_VM_ID) {
		ret = ffa_error(FFA_RET_INVALID_PARAMETERS);
		goto out;
	}

	if (memory_region->ep_count != 1) {
		/* pKVM doesn't support multi-way memory sharing for now. */
		ret = ffa_error(FFA_RET_INVALID_PARAMETERS);
		goto out;
	}

	if (memory_region->ep_mem_access[0].receiver != TEE_VM_ID) {
		/* pKVM only supports FF-A memory sharing to SPs, not normal world VMs. */
		ret = ffa_error(FFA_RET_INVALID_PARAMETERS);
		goto out;
	}

	hyp_spin_lock(&host_kvm.lock);
	hyp_spin_lock(&spmd.lock);

	if (spmd.mailbox_state != MAILBOX_STATE_EMPTY) {
		ret = ffa_error(FFA_RET_BUSY);
		goto out_unlock;
	}

	ret = ffa_memory_tee_send(&host_kvm.pgt, memory_region, length,
				  fragment_length, share_func,
				  &descriptor_pool);
	/*
	 * ffa_tee_memory_send takes ownership of the memory_region (and frees
	 * it on failure), so make sure we don't free it.
	 */
	memory_region = NULL;

out_unlock:
	hyp_spin_unlock(&host_kvm.lock);
	hyp_spin_unlock(&spmd.lock);

out:
	if (memory_region != NULL) {
		/* Free memory_region. */
		hyp_put_page(&descriptor_pool, memory_region);
	}

	return ret;
}

struct arm_smccc_1_2_regs ffa_mem_frag_tx(ffa_memory_handle_t handle,
					  uint32_t fragment_length,
					  ffa_vm_id_t sender_vm_id)
{
	const void *from_msg;
	void *fragment_copy;
	struct arm_smccc_1_2_regs ret;

	/* Sender ID MBZ at virtual instance. */
	if (sender_vm_id != 0) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	/*
	 * Check that the sender has configured its send buffer. If the TX
	 * mailbox at from_msg is configured (i.e. from_msg != NULL) then it can
	 * be safely accessed after releasing the lock since the TX mailbox
	 * address can only be configured once.
	 */
	hyp_spin_lock(&host_kvm.lock);
	from_msg = host_kvm.tx_buffer;
	hyp_spin_unlock(&host_kvm.lock);

	if (from_msg == NULL) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	/*
	 * Copy the fragment to a fresh page from the memory pool. This prevents
	 * the sender from changing it underneath us, and also lets us keep it
	 * around in the share state table if needed.
	 */
	if (fragment_length > MAILBOX_SIZE) {
		pr_warn("Fragment length larger than mailbox size.");
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}
	if (fragment_length < sizeof(struct ffa_mem_region_addr_range) ||
	    fragment_length % sizeof(struct ffa_mem_region_addr_range) != 0) {
		pr_warn("Invalid fragment length.");
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}
	fragment_copy =
		hyp_alloc_pages(&descriptor_pool, get_order(MAILBOX_SIZE));
	if (fragment_copy == NULL) {
		pr_warn("Failed to allocate fragment copy.");
		return ffa_error(FFA_RET_NO_MEMORY);
	}
	memcpy(fragment_copy, from_msg, fragment_length);

	/*
	 * pKVM doesn't support fragmentation of memory retrieve requests
	 * (because it doesn't support caller-specified mappings, so a request
	 * will never be larger than a single page), so this must be part of a
	 * memory send (i.e. donate, lend or share) request.
	 *
	 * We can tell from the handle whether the memory transaction is for the
	 * TEE or not.
	 */
	if ((handle & FFA_MEMORY_HANDLE_ALLOCATOR_MASK) ==
	    FFA_MEMORY_HANDLE_ALLOCATOR_HYPERVISOR) {
		/* Sending memory to normal world VMs is not supported. */
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	} else {
		hyp_spin_lock(&host_kvm.lock);
		hyp_spin_lock(&spmd.lock);

		/*
		 * The TEE RX buffer state is checked in
		 * `ffa_memory_tee_send_continue` rather than here, as we need
		 * to return `FFA_MEM_FRAG_RX` with the current offset rather
		 * than FFA_ERROR FFA_BUSY in case it is busy.
		 */

		ret = ffa_memory_tee_send_continue(&host_kvm.pgt, fragment_copy,
						   fragment_length, handle,
						   &descriptor_pool);
		/*
		 * `ffa_memory_tee_send_continue` takes ownership of the
		 * fragment_copy (and frees it on failure), so we don't need to
		 * free it here.
		 */

		hyp_spin_unlock(&host_kvm.lock);
		hyp_spin_unlock(&spmd.lock);
	}

	return ret;
}

/**
 * ffa_rxtx_map() - Handles the FFA_RXTX_MAP function.
 * @tx_address: The IPA of the TX buffer.
 * @rx_address: The IPA of the RX buffer.
 * @page_count: The length of the RX and TX buffers, as a multiple of
 *              FFA_PAGE_SIZE.
 *
 * Return: FFA_SUCCESS, or an appropriate FFA_ERROR.
 */
static struct arm_smccc_1_2_regs ffa_rxtx_map(hpa_t tx_address,
					      hpa_t rx_address, u32 page_count)
{
	struct arm_smccc_1_2_regs ret;

	pr_info("RXTX_MAP");

	/* We only support a fixed size of RX/TX buffers. */
	if (page_count != MAILBOX_SIZE / FFA_PAGE_SIZE)
		return ffa_error(FFA_RET_INVALID_PARAMETERS);

	/* Fail if addresses are not page-aligned. */
	if (!IS_ALIGNED(tx_address, PAGE_SIZE) ||
	    !IS_ALIGNED(rx_address, PAGE_SIZE)) {
		return ffa_error(FFA_RET_INVALID_PARAMETERS);
	}

	/* Fail if the same page is used for the send and receive pages. */
	if (tx_address == rx_address)
		return ffa_error(FFA_RET_INVALID_PARAMETERS);

	/* Lock host VM info and hypervisor page table. */
	hyp_spin_lock(&host_kvm.lock);
	hyp_spin_lock(&pkvm_pgd_lock);

	/* Ensure that buffers are not already setup. */
	if (host_kvm.tx_buffer != NULL || host_kvm.rx_buffer != NULL) {
		pr_warn("Buffers already set up");
		ret = ffa_error(FFA_RET_DENIED);
		goto out;
	}

	// TODO: Check that MAILBOX_SIZE == page size
	/*
	 * Ensure that the VM is allowed to share the pages, i.e. it exclusively
	 * owns them.
	 */
	if (__pkvm_host_check_share_hyp_prot(tx_address, MAILBOX_SIZE,
					     PAGE_HYP_RO) != 0) {
		pr_warn("TX buffer permissions are wrong");
		ret = ffa_error(FFA_RET_DENIED);
		goto out;
	}
	if (__pkvm_host_check_share_hyp_prot(rx_address, MAILBOX_SIZE,
					     PAGE_HYP) != 0) {
		pr_warn("RX buffer permissions are wrong");
		ret = ffa_error(FFA_RET_DENIED);
		goto out;
	}

	/*
	 * Mark as no longer exclusive to the VM, and map in the hypervisor
	 * stage-1 page table. This takes pkvm_pgd_lock when needed.
	 */
	if (__pkvm_host_share_hyp_prot(tx_address, MAILBOX_SIZE, PAGE_HYP_RO,
				       &host_kvm.tx_buffer) != 0) {
		pr_warn("Failed to share TX buffer");
		ret = ffa_error(FFA_RET_NO_MEMORY);
		goto out;
	}
	if (__pkvm_host_share_hyp_prot(rx_address, MAILBOX_SIZE, PAGE_HYP,
				       &host_kvm.rx_buffer) != 0) {
		pr_warn("Failed to share RX buffer");
		ret = ffa_error(FFA_RET_NO_MEMORY);
		goto out;
	}

	// TODO: Do we need to do something about waiters?

	ret = (struct arm_smccc_1_2_regs){
		.a0 = FFA_SUCCESS,
	};

out:
	hyp_spin_unlock(&host_kvm.lock);
	hyp_spin_unlock(&pkvm_pgd_lock);

	return ret;
}

bool kvm_host_ffa_handler(struct kvm_cpu_context *host_ctxt)
{
	struct arm_smccc_1_2_regs ret;
	DECLARE_REG(u64, func_id, host_ctxt, 0);
	DECLARE_REG(u64, a1, host_ctxt, 1);
	DECLARE_REG(u64, a2, host_ctxt, 2);
	DECLARE_REG(u64, a3, host_ctxt, 3);
	DECLARE_REG(u64, a4, host_ctxt, 4);
	DECLARE_REG(u64, a5, host_ctxt, 5);
	DECLARE_REG(u64, a6, host_ctxt, 6);
	DECLARE_REG(u64, a7, host_ctxt, 7);

	if (!is_ffa_call(func_id))
		return false;

	switch (func_id) {
	case FFA_ERROR:
	case FFA_SUCCESS:
	case FFA_INTERRUPT:
	case FFA_FEATURES:
	case FFA_RX_RELEASE:
	case FFA_PARTITION_INFO_GET:
	case FFA_MSG_POLL: // TODO: Need to copy buffer on return
	case FFA_MSG_WAIT: // TODO: Need to copy buffer on return
	case FFA_YIELD:
	case FFA_RUN:
	case FFA_MSG_SEND: // TODO: Need to copy buffer
	case FFA_MSG_SEND_DIRECT_REQ:
	case FFA_FN64_MSG_SEND_DIRECT_REQ:
	case FFA_MSG_SEND_DIRECT_RESP:
	case FFA_FN64_MSG_SEND_DIRECT_RESP:
	case FFA_NORMAL_WORLD_RESUME: {
		const struct arm_smccc_1_2_regs args = { .a0 = func_id,
							 .a1 = a1,
							 .a2 = a2,
							 .a3 = a3,
							 .a4 = a4,
							 .a5 = a5,
							 .a6 = a6,
							 .a7 = a7 };
		// These calls don't contain any addresses, so we can safely forward them to EL3.
		arm_smccc_1_2_smc(&args, &ret);
		break;
	}
	case FFA_VERSION:
		ret = ffa_version(a1);
		break;
	case FFA_ID_GET:
		ret = ffa_id_get();
		break;
	case FFA_RXTX_MAP: // Should this be allowed?
	case FFA_FN64_RXTX_MAP:
		ret = ffa_rxtx_map(a1, a2, a3);
		break;
	case FFA_RXTX_UNMAP:
	case FFA_MEM_DONATE:
	case FFA_FN64_MEM_DONATE:
	case FFA_MEM_LEND:
	case FFA_FN64_MEM_LEND:
	case FFA_MEM_SHARE:
	case FFA_FN64_MEM_SHARE:
		ret = ffa_mem_send(func_id, a1, a2, a3, a4);
		break;
	case FFA_MEM_FRAG_TX:
		ret = ffa_mem_frag_tx(ffa_assemble_handle(a1, a2), a3,
				      (a4 >> 16) & 0xffff);
		break;
	case FFA_MEM_RECLAIM:
		ret = ffa_mem_reclaim(ffa_assemble_handle(a1, a2), a3);
		break;
	case FFA_MEM_FRAG_RX:
	case FFA_MEM_RETRIEVE_REQ:
	case FFA_FN64_MEM_RETRIEVE_REQ:
	case FFA_MEM_RETRIEVE_RESP:
	case FFA_MEM_RELINQUISH:
	case FFA_MEM_OP_PAUSE:
	case FFA_MEM_OP_RESUME:
		// TODO: Implement
	default:
		ret = ffa_error(FFA_RET_NOT_SUPPORTED);
	}

	cpu_reg(host_ctxt, 0) = ret.a0;
	cpu_reg(host_ctxt, 1) = ret.a1;
	cpu_reg(host_ctxt, 2) = ret.a2;
	cpu_reg(host_ctxt, 3) = ret.a3;
	cpu_reg(host_ctxt, 4) = ret.a4;
	cpu_reg(host_ctxt, 5) = ret.a5;
	cpu_reg(host_ctxt, 6) = ret.a6;
	cpu_reg(host_ctxt, 7) = ret.a7;
	return true;
}
