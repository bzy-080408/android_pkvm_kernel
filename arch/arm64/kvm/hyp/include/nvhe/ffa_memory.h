/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include <linux/arm-smccc.h>

struct hyp_pool;

struct arm_smccc_1_2_regs
ffa_memory_tee_send(struct kvm_pgtable *from_pgt,
		    struct ffa_mem_region *memory_region,
		    uint32_t memory_share_length, uint32_t fragment_length,
		    uint32_t share_func, struct hyp_pool *page_pool);
struct arm_smccc_1_2_regs ffa_memory_tee_send_continue(
	struct kvm_pgtable *from_pgt, void *fragment, uint32_t fragment_length,
	ffa_memory_handle_t handle, struct hyp_pool *page_pool);
