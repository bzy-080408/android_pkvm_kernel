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

	if (!is_ffa_call(func_id))
		return false;

	switch (func_id) {
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
