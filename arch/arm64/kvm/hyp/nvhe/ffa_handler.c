// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include <linux/arm-smccc.h>
#include <linux/arm_ffa.h>
#include <nvhe/ffa.h>
#include <nvhe/ffa_handler.h>
#include <nvhe/trap_handler.h>

// TODO: Initialise this properly
u64 __ro_after_init smccc_has_sve_hint;

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
	case FFA_MSG_POLL:
	case FFA_MSG_WAIT:
	case FFA_YIELD:
	case FFA_RUN:
	case FFA_MSG_SEND:
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
	case FFA_RXTX_MAP:
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
