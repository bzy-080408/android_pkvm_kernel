// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include <asm/kvm_pgtable.h>
#include <linux/stddef.h>
#include <linux/types.h>
#include <nvhe/memory.h>
#include <nvhe/mm.h>

void *hyp_map(phys_addr_t start, size_t length, enum kvm_pgtable_prot prot)
{
	void *start_va = hyp_phys_to_virt(start);
	void *end_va = hyp_phys_to_virt(start + length);

	int ret = pkvm_create_mappings(start_va, end_va, prot);

	if (ret == 0) {
		return start_va;
	} else {
		// TODO: Do something about the error?
		return NULL;
	}
}

int hyp_unmap(phys_addr_t start, size_t length)
{
	void *start_va = hyp_phys_to_virt(start);
	void *end_va = hyp_phys_to_virt(start + length);

	return pkvm_destroy_mappings(start_va, end_va);
}
