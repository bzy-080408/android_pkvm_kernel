/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2020 Google LLC
 * Author: Will Deacon <will@kernel.org>
 */

#ifndef __KVM_ARM_SPCI_H
#define __KVM_ARM_SPCI_H

#include <linux/of_reserved_mem.h>

enum kvm_spci_mem_prot {
	KVM_SPCI_MEM_PROT_X	= 1 << 0,
	KVM_SPCI_MEM_PROT_W	= 1 << 1,
	KVM_SPCI_MEM_PROT_R	= 1 << 2,
};

struct kvm_spci_memory {
	struct reserved_mem	*rmem;		/* Physical carveout */
	phys_addr_t		ipa_base;
	phys_addr_t		ipa_size;	/* Size of guest region */
	enum kvm_spci_mem_prot	prot;
};

struct kvm_spci_partition {
	struct list_head	list;
	int			id;
	uuid_t			uuid;
	u64			entry_point;
	int			nr_vcpus;
	int			nr_mems;
	bool			is_32bit;
	struct kvm_spci_memory	*mems[];
};

#ifdef CONFIG_KVM_ARM_SPCI

int kvm_spci_init(void);

#else

static inline int kvm_spci_init(void) { return 0; }

#endif /* CONFIG_KVM_ARM_SPCI */
#endif	/* __KVM_ARM_SPCI_H */
