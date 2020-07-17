/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012,2013 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#ifndef __ARM64_KVM_PSCI_H__
#define __ARM64_KVM_PSCI_H__

#include <asm/cputype.h>
#include <asm/kvm_host.h>

#define AFFINITY_MASK(level)	~((0x1UL << ((level) * MPIDR_LEVEL_BITS)) - 1)

static unsigned long kvm_psci_affinity_mask(unsigned long affinity_level)
{
	if (affinity_level <= 3)
		return MPIDR_HWID_BITMASK & AFFINITY_MASK(affinity_level);

	return 0;
}

static void kvm_psci_narrow_to_32bit(struct kvm_vcpu *vcpu)
{
	int i;

	/*
	 * Zero the input registers' upper 32 bits. They will be fully
	 * zeroed on exit, so we're fine changing them in place.
	 */
	for (i = 1; i < 4; i++)
		vcpu_set_reg(vcpu, i, lower_32_bits(vcpu_get_reg(vcpu, i)));
}

#endif /* __ARM64_KVM_PSCI_H__ */
