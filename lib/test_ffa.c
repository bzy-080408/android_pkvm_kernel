// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 *
 * Kernel module for testing FF-A on aarch64, possibly via the pKVM FF-A implementation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/arm_ffa.h>
#include <linux/arm-smccc.h>
#include "../tools/testing/selftests/kselftest_module.h"

/** FF-A version 1.0. */
#define FFA_VERSION_1_0 (1 << 16 | 0)

KSTM_MODULE_GLOBALS();

/** Calling an unsupported FF-A function should result in an error. */
static int __init test_invalid_smc(void)
{
	struct arm_smccc_1_2_regs ret;
	const struct arm_smccc_1_2_regs args = { .a0 = FFA_MEM_OP_PAUSE };

	arm_smccc_1_2_smc(&args, &ret);

	if (ret.a0 != FFA_ERROR && ret.a2 == FFA_RET_NOT_SUPPORTED) {
		pr_err("FFA_MEM_OP_PAUSE: expected FFA_ERROR NOT_SUPPORTED (%#x %#x) but got %#x %#x",
		       FFA_ERROR, FFA_RET_NOT_SUPPORTED, ret.a0, ret.a2);
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

static void __init selftest(void)
{
	pr_info("test_invalid_smc");
	KSTM_CHECK_ZERO(test_invalid_smc());
	pr_info("test_get_version");
	KSTM_CHECK_ZERO(test_get_version());
}

KSTM_MODULE_LOADERS(test_ffa);
MODULE_AUTHOR("Andrew Walbran <qwandor@google.com>");
MODULE_LICENSE("GPL");
