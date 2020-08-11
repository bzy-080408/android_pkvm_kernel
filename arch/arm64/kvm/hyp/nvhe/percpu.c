// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google LLC
 * Author: David Brazdil <dbrazdil@google.com>
 */

#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#include <nvhe/memory.h>

/* nVHE copy of data structures tracking available CPU cores. */
u64 __cpu_logical_map[NR_CPUS];

u64 cpu_logical_map(int cpu) {
	if (cpu < 0 || cpu >= ARRAY_SIZE(__cpu_logical_map))
		hyp_panic();

	return __cpu_logical_map[cpu];
}

unsigned long __hyp_per_cpu_offset(unsigned int cpu)
{
	unsigned long *cpu_base_array;
	unsigned long this_cpu_base, elf_base;

	if (cpu >= ARRAY_SIZE(kvm_arm_hyp_percpu_base))
		hyp_panic();

	cpu_base_array = kern_hyp_va(&kvm_arm_hyp_percpu_base[0]);
	this_cpu_base = (unsigned long)__hyp_va(cpu_base_array[cpu]);
	elf_base = (unsigned long)&__per_cpu_start;
	return this_cpu_base - elf_base;
}
