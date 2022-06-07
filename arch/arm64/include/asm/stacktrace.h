/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 ARM Ltd.
 */
#ifndef __ASM_STACKTRACE_H
#define __ASM_STACKTRACE_H

#include <linux/kvm_host.h>
#include <linux/percpu.h>
#include <linux/sched.h>
#include <linux/sched/task_stack.h>
#include <linux/types.h>
#include <linux/llist.h>

#include <asm/memory.h>
#include <asm/ptrace.h>
#include <asm/sdei.h>

enum stack_type {
#ifndef __KVM_NVHE_HYPERVISOR__
	STACK_TYPE_TASK,
	STACK_TYPE_IRQ,
	STACK_TYPE_SDEI_NORMAL,
	STACK_TYPE_SDEI_CRITICAL,
#else /* __KVM_NVHE_HYPERVISOR__ */
	STACK_TYPE_HYP,
#endif /* !__KVM_NVHE_HYPERVISOR__ */
	STACK_TYPE_OVERFLOW,
	STACK_TYPE_UNKNOWN,
	__NR_STACK_TYPES
};

struct stack_info {
	unsigned long low;
	unsigned long high;
	enum stack_type type;
};

static inline bool on_stack(unsigned long sp, unsigned long size,
			    unsigned long low, unsigned long high,
			    enum stack_type type, struct stack_info *info)
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

#ifndef __KVM_NVHE_HYPERVISOR__
extern void dump_backtrace(struct pt_regs *regs, struct task_struct *tsk,
			   const char *loglvl);

extern void hyp_dump_backtrace(unsigned long hyp_offset);

DECLARE_PER_CPU(unsigned long, kvm_arm_hyp_stacktrace_page);
DECLARE_PER_CPU(unsigned long *, irq_stack_ptr);

static inline bool on_irq_stack(unsigned long sp, unsigned long size,
				struct stack_info *info)
{
	unsigned long low = (unsigned long)raw_cpu_read(irq_stack_ptr);
	unsigned long high = low + IRQ_STACK_SIZE;

	return on_stack(sp, size, low, high, STACK_TYPE_IRQ, info);
}

static inline bool on_task_stack(const struct task_struct *tsk,
				 unsigned long sp, unsigned long size,
				 struct stack_info *info)
{
	unsigned long low = (unsigned long)task_stack_page(tsk);
	unsigned long high = low + THREAD_SIZE;

	return on_stack(sp, size, low, high, STACK_TYPE_TASK, info);
}

#ifdef CONFIG_VMAP_STACK
DECLARE_PER_CPU(unsigned long [OVERFLOW_STACK_SIZE/sizeof(long)], overflow_stack);

static inline bool on_overflow_stack(unsigned long sp, unsigned long size,
				struct stack_info *info)
{
	unsigned long low = (unsigned long)raw_cpu_ptr(overflow_stack);
	unsigned long high = low + OVERFLOW_STACK_SIZE;

	return on_stack(sp, size, low, high, STACK_TYPE_OVERFLOW, info);
}
#else
static inline bool on_overflow_stack(unsigned long sp, unsigned long size,
			struct stack_info *info) { return false; }
#endif
#else /* __KVM_NVHE_HYPERVISOR__ */

extern void hyp_save_backtrace(void);

DECLARE_PER_CPU(unsigned long [PAGE_SIZE/sizeof(long)], overflow_stack);
DECLARE_PER_CPU(struct kvm_nvhe_init_params, kvm_init_params);

static inline bool on_overflow_stack(unsigned long sp, unsigned long size,
				 struct stack_info *info)
{
	unsigned long low = (unsigned long)this_cpu_ptr(overflow_stack);
	unsigned long high = low + PAGE_SIZE;

	return on_stack(sp, size, low, high, STACK_TYPE_OVERFLOW, info);
}

static inline bool on_hyp_stack(unsigned long sp, unsigned long size,
				 struct stack_info *info)
{
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);
	unsigned long high = params->stack_hyp_va;
	unsigned long low = high - PAGE_SIZE;

	return on_stack(sp, size, low, high, STACK_TYPE_HYP, info);
}
#endif /* !__KVM_NVHE_HYPERVISOR__ */

/*
 * We can only safely access per-cpu stacks from current in a non-preemptible
 * context.
 */
static inline bool on_accessible_stack(const struct task_struct *tsk,
				       unsigned long sp, unsigned long size,
				       struct stack_info *info)
{
	if (info)
		info->type = STACK_TYPE_UNKNOWN;

	if (on_overflow_stack(sp, size, info))
		return true;

#ifndef __KVM_NVHE_HYPERVISOR__
	if (on_task_stack(tsk, sp, size, info))
		return true;
	if (tsk != current || preemptible())
		return false;
	if (on_irq_stack(sp, size, info))
		return true;
	if (on_sdei_stack(sp, size, info))
		return true;
#else /* __KVM_NVHE_HYPERVISOR__ */
	if (on_hyp_stack(sp, size, info))
		return true;
#endif /* !__KVM_NVHE_HYPERVISOR__ */

	return false;
}

#endif	/* __ASM_STACKTRACE_H */
