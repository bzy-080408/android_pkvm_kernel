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

KSTM_MODULE_GLOBALS();

static uint8_t *tx_buffer;
static uint8_t *rx_buffer;

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

static int __init test_rxtx_map(void)
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

static void __init selftest(void)
{
	tx_buffer = get_zeroed_page(GFP_ATOMIC);
	if (tx_buffer == NULL)
		pr_err("Failed to allocate TX buffer");
	rx_buffer = get_zeroed_page(GFP_ATOMIC);
	if (rx_buffer == NULL)
		pr_err("Failed to allocate RX buffer");

	pr_info("test_invalid_smc");
	KSTM_CHECK_ZERO(test_invalid_smc());
	pr_info("test_get_version");
	KSTM_CHECK_ZERO(test_get_version());
	pr_info("test_rxtx_map");
	KSTM_CHECK_ZERO(test_rxtx_map());
}

KSTM_MODULE_LOADERS(test_ffa);
MODULE_AUTHOR("Andrew Walbran <qwandor@google.com>");
MODULE_LICENSE("GPL");
