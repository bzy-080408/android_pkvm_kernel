// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include <asm/kvm_pgtable.h>
#include <linux/arm-smccc.h>
#include <linux/arm_ffa.h>
#include <linux/kvm_types.h>
#include <nvhe/ffa.h>
#include <nvhe/ffa_handler.h>
#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/spinlock.h>
#include <nvhe/trap_handler.h>
#include <linux/align.h>

// TODO: Initialise this properly
u64 __ro_after_init smccc_has_sve_hint;

/*
 * The size of RX/TX buffer which we support. The implementation assumes that
 * this is the same size as the stage 2 page table page size.
 */
// TODO: Support other page sizes before this goes upstream.
#define MAILBOX_SIZE 4096

/** Constructs an FF-A error return value with the specified error code. */
static struct arm_smccc_1_2_regs ffa_error(u64 error_code)
{
	return (struct arm_smccc_1_2_regs){ .a0 = FFA_ERROR, .a2 = error_code };
}

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
		ret = ffa_error(FFA_RET_DENIED);
		goto out;
	}
	if (__pkvm_host_check_share_hyp_prot(rx_address, MAILBOX_SIZE,
					     PAGE_HYP) != 0) {
		ret = ffa_error(FFA_RET_DENIED);
		goto out;
	}

	/*
	 * Mark as no longer exclusive to the VM, and map in the hypervisor
	 * stage-1 page table. This takes pkvm_pgd_lock when needed.
	 */
	if (__pkvm_host_share_hyp_prot(tx_address, MAILBOX_SIZE, PAGE_HYP_RO,
				       &host_kvm.tx_buffer) != 0) {
		ret = ffa_error(FFA_RET_NO_MEMORY);
		goto out;
	}
	if (__pkvm_host_share_hyp_prot(rx_address, MAILBOX_SIZE, PAGE_HYP,
				       &host_kvm.rx_buffer) != 0) {
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
	case FFA_ID_GET:
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
	case FFA_MEM_RETRIEVE_REQ:
	case FFA_FN64_MEM_RETRIEVE_REQ:
	case FFA_MEM_RETRIEVE_RESP:
	case FFA_MEM_RELINQUISH:
	case FFA_MEM_OP_PAUSE:
	case FFA_MEM_OP_RESUME:
	case FFA_MEM_FRAG_RX:
	case FFA_MEM_FRAG_TX:
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
