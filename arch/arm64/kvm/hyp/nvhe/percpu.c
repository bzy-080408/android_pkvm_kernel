// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google LLC
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

unsigned long __hyp_per_cpu_offset(unsigned int cpu)
{
	unsigned long *array;

	/* XXX - TODO: check cpu id */
	array = kern_hyp_va(kvm_arm_hyp_percpu_base);
	return kern_hyp_va(array[cpu]) - (unsigned long)&__per_cpu_start;
}
