/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Stack unwinder for EL2 nVHE hypervisor.
 *
 * Code mostly copied from the arm64 kernel stack unwinder:
 * arch/arm64/include/asm/stacktrace.h
 */

#ifndef __KVM_HYP_STACKTRACE_H
#define __KVM_HYP_STACKTRACE_H

#include <asm/kvm_hyp.h>

DECLARE_PER_CPU(unsigned long [PAGE_SIZE/sizeof(long)], hyp_overflow_stack);

enum hyp_stack_type {
	HYP_STACK_TYPE_UNKNOWN,
	HYP_STACK_TYPE_HYP,
	HYP_STACK_TYPE_OVERFLOW,
	__NR_HYP_STACK_TYPES
};

struct hyp_stack_info {
	unsigned long low;
	unsigned long high;
	enum hyp_stack_type type;
};

/*
 * A snapshot of a frame record or fp/lr register values, along with some
 * accounting information necessary for robust unwinding.
 *
 * @fp:          The fp value in the frame record (or the real fp)
 * @pc:          The lr value in the frame record (or the real lr)
 *
 * @stacks_done: Stacks which have been entirely unwound, for which it is no
 *               longer valid to unwind to.
 *
 * @prev_fp:     The fp that pointed to this frame record, or a synthetic value
 *               of 0. This is used to ensure that within a stack, each
 *               subsequent frame record is at an increasing address.
 * @prev_type:   The type of stack this frame record was on, or a synthetic
 *               value of STACK_TYPE_UNKNOWN. This is used to detect a
 *               transition from one stack to another.
 */
struct hyp_stackframe {
	unsigned long fp;
	unsigned long pc;
	DECLARE_BITMAP(stacks_done, __NR_HYP_STACK_TYPES);
	unsigned long prev_fp;
	enum hyp_stack_type prev_type;
};

static inline bool hyp_on_stack(unsigned long sp, unsigned long size,
				unsigned long low, unsigned long high,
				enum hyp_stack_type type,
				struct hyp_stack_info *info)
{
	if (!low)
		return false;

	if (sp < low || sp + size < sp || sp + size > high)
		return false;

	if (info) {
		info->low = low;
		info->high = high;
		info->type = type;
	}
	return true;
}

static inline bool hyp_on_overflow_stack(unsigned long sp, unsigned long size,
				 struct hyp_stack_info *info)
{
	unsigned long low = (unsigned long)this_cpu_ptr(hyp_overflow_stack);
	unsigned long high = low + PAGE_SIZE;

	return hyp_on_stack(sp, size, low, high, HYP_STACK_TYPE_OVERFLOW, info);
}

static inline bool hyp_on_hyp_stack(unsigned long sp, unsigned long size,
				 struct hyp_stack_info *info)
{
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);
	unsigned long high = params->stack_hyp_va;
	unsigned long low = high - PAGE_SIZE;

	return hyp_on_stack(sp, size, low, high, HYP_STACK_TYPE_HYP, info);
}

static inline bool hyp_on_accessible_stack(unsigned long sp, unsigned long size,
				       struct hyp_stack_info *info)
{
	if (info)
		info->type = HYP_STACK_TYPE_UNKNOWN;

	if (hyp_on_hyp_stack(sp, size, info))
		return true;
	if (hyp_on_overflow_stack(sp, size, info))
		return true;

	return false;
}

void hyp_dump_backtrace(void);

#endif /* __KVM_HYP_STACKTRACE_H */
