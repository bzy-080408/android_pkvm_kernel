// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack tracing support
 *
 * Copyright (C) 2012 ARM Ltd.
 */
#include <linux/kernel.h>
#include <linux/export.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/sched/debug.h>
#include <linux/sched/task_stack.h>
#include <linux/stacktrace.h>

#include <asm/irq.h>
#include <asm/pointer_auth.h>
#include <asm/stack_pointer.h>
#include <asm/stacktrace.h>

/*
 * Unwind from one frame record (A) to the next frame record (B).
 *
 * We terminate early if the location of B indicates a malformed chain of frame
 * records (e.g. a cycle), determined based on the location and fp value of A
 * and the location (but not the fp value) of B.
 */
static int notrace __unwind_next(struct task_struct *tsk,
				 struct unwind_state *state,
				 struct stack_info *info)
{
	unsigned long fp = state->fp;

	if (fp & 0x7)
		return -EINVAL;

	if (!tsk)
		tsk = current;

	if (!on_accessible_stack(tsk, fp, 16, info))
		return -EINVAL;

	if (test_bit(info->type, state->stacks_done))
		return -EINVAL;

	/*
	 * As stacks grow downward, any valid record on the same stack must be
	 * at a strictly higher address than the prior record.
	 *
	 * Stacks can nest in several valid orders, e.g.
	 *
	 * TASK -> IRQ -> OVERFLOW -> SDEI_NORMAL
	 * TASK -> SDEI_NORMAL -> SDEI_CRITICAL -> OVERFLOW
	 * HYP -> OVERFLOW
	 *
	 * ... but the nesting itself is strict. Once we transition from one
	 * stack to another, it's never valid to unwind back to that first
	 * stack.
	 */
	if (info->type == state->prev_type) {
		if (fp <= state->prev_fp)
			return -EINVAL;
	} else {
		set_bit(state->prev_type, state->stacks_done);
	}

	/*
	 * Record this frame record's values and location. The prev_fp and
	 * prev_type are only meaningful to the next unwind_next() invocation.
	 */
	state->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
	state->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8));
	state->prev_fp = fp;
	state->prev_type = info->type;

	return 0;
}
NOKPROBE_SYMBOL(__unwind_next);

int notrace unwind_next(struct task_struct *tsk,
			       struct unwind_state *state);

void notrace unwind(struct task_struct *tsk,
			   struct unwind_state *state,
			   bool (*fn)(void *, unsigned long), void *data)
{
	while (1) {
		int ret;

		if (!fn(data, state->pc))
			break;
		ret = unwind_next(tsk, state);
		if (ret < 0)
			break;
	}
}
NOKPROBE_SYMBOL(unwind);

#ifndef __KVM_NVHE_HYPERVISOR__
int notrace unwind_next(struct task_struct *tsk,
			       struct unwind_state *state)
{
	struct stack_info info;
	int err;

	/* Final frame; nothing to unwind */
	if (state->fp == (unsigned long)task_pt_regs(tsk)->stackframe)
		return -ENOENT;

	err = __unwind_next(tsk, state, &info);
	if (err)
		return err;

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	if (tsk->ret_stack &&
		(ptrauth_strip_insn_pac(state->pc) == (unsigned long)return_to_handler)) {
		struct ftrace_ret_stack *ret_stack;
		/*
		 * This is a case where function graph tracer has
		 * modified a return address (LR) in a stack frame
		 * to hook a function return.
		 * So replace it to an original value.
		 */
		ret_stack = ftrace_graph_get_ret_stack(tsk, state->graph++);
		if (WARN_ON_ONCE(!ret_stack))
			return -EINVAL;
		state->pc = ret_stack->ret;
	}
#endif /* CONFIG_FUNCTION_GRAPH_TRACER */

	state->pc = ptrauth_strip_insn_pac(state->pc);

	/*
	 * Frames created upon entry from EL0 have NULL FP and PC values, so
	 * don't bother reporting these. Frames created by __noreturn functions
	 * might have a valid FP even if PC is bogus, so only terminate where
	 * both are NULL.
	 */
	if (!state->fp && !state->pc)
		return -EINVAL;

	return 0;
}
NOKPROBE_SYMBOL(unwind_next);

static void dump_backtrace_entry(unsigned long where, const char *loglvl)
{
	printk("%s %pS\n", loglvl, (void *)where);
}

void dump_backtrace(struct pt_regs *regs, struct task_struct *tsk,
		    const char *loglvl)
{
	struct unwind_state state;
	int skip = 0;

	pr_debug("%s(regs = %p tsk = %p)\n", __func__, regs, tsk);

	if (regs) {
		if (user_mode(regs))
			return;
		skip = 1;
	}

	if (!tsk)
		tsk = current;

	if (!try_get_task_stack(tsk))
		return;

	if (tsk == current) {
		unwind_init(&state,
				(unsigned long)__builtin_frame_address(0),
				(unsigned long)dump_backtrace);
	} else {
		/*
		 * task blocked in __switch_to
		 */
		unwind_init(&state,
				thread_saved_fp(tsk),
				thread_saved_pc(tsk));
	}

	printk("%sCall trace:\n", loglvl);
	do {
		/* skip until specified stack frame */
		if (!skip) {
			dump_backtrace_entry(state.pc, loglvl);
		} else if (state.fp == regs->regs[29]) {
			skip = 0;
			/*
			 * Mostly, this is the case where this function is
			 * called in panic/abort. As exception handler's
			 * stack frame does not contain the corresponding pc
			 * at which an exception has taken place, use regs->pc
			 * instead.
			 */
			dump_backtrace_entry(regs->pc, loglvl);
		}
	} while (!unwind_next(tsk, &state));

	put_task_stack(tsk);
}
EXPORT_SYMBOL_GPL(dump_backtrace);

void show_stack(struct task_struct *tsk, unsigned long *sp, const char *loglvl)
{
	dump_backtrace(NULL, tsk, loglvl);
	barrier();
}

#ifdef CONFIG_STACKTRACE

noinline notrace void arch_stack_walk(stack_trace_consume_fn consume_entry,
			      void *cookie, struct task_struct *task,
			      struct pt_regs *regs)
{
	struct unwind_state state;

	if (regs)
		unwind_init(&state, regs->regs[29], regs->pc);
	else if (task == current)
		unwind_init(&state,
				(unsigned long)__builtin_frame_address(1),
				(unsigned long)__builtin_return_address(0));
	else
		unwind_init(&state, thread_saved_fp(task),
				thread_saved_pc(task));

	unwind(task, &state, consume_entry, cookie);
}

#endif

/**
 * Symbolizes and dumps the hypervisor backtrace from the shared
 * stacktrace page.
 */
#ifdef CONFIG_KVM
noinline notrace void hyp_dump_backtrace(unsigned long hyp_offset)
{
	unsigned long *stacktrace_pos =
		(unsigned long *)*this_cpu_ptr(&kvm_arm_hyp_stacktrace_page);
	unsigned long va_mask = GENMASK_ULL(vabits_actual - 1, 0);
	unsigned long pc = *stacktrace_pos++;

	kvm_err("nVHE HYP call trace:\n");

	while (pc) {
		pc &= va_mask;		/* Mask tags */
		pc += hyp_offset;	/* Convert to kern addr */
		kvm_err("[<%016lx>] %pB\n", pc, (void *)(pc + kaslr_offset()));
		pc = *stacktrace_pos++;
	}

	kvm_err("---- end of nVHE HYP call trace ----\n");
}
#else /* !CONFIG_KVM */
noinline notrace void hyp_dump_backtrace(unsigned long hyp_offset)
{
}
#endif /* CONFIG_KVM */
#else /* __KVM_NVHE_HYPERVISOR__ */
DEFINE_PER_CPU(unsigned long [PAGE_SIZE/sizeof(long)], overflow_stack)
	__aligned(16);

int notrace unwind_next(struct task_struct *tsk,
			       struct unwind_state *state)
{
	struct stack_info info;

	return __unwind_next(tsk, state, &info);
}

/**
 * Saves a hypervisor stacktrace entry (address) to the shared stacktrace page.
 */
static bool hyp_save_backtrace_entry(void *arg, unsigned long where)
{
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);
	unsigned long **stacktrace_pos = (unsigned long **)arg;
	unsigned long stacktrace_start, stacktrace_end;

	stacktrace_start = (unsigned long)params->stacktrace_hyp_va;
	stacktrace_end = stacktrace_start + PAGE_SIZE - (2 * sizeof(long));

	if ((unsigned long) *stacktrace_pos > stacktrace_end)
		return false;

	/* Save the entry to the current pos in stacktrace page */
	**stacktrace_pos = where;

	/* A zero entry delimits the end of the stacktrace. */
	*(*stacktrace_pos + 1) = 0UL;

	/* Increment the current pos */
	++*stacktrace_pos;

	return true;
}

/**
 * Saves hypervisor stacktrace to the shared stacktrace page.
 */
noinline notrace void hyp_save_backtrace(void)
{
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);
	void *stacktrace_start = (void *)params->stacktrace_hyp_va;
	struct unwind_state state;

	unwind_init(&state, (unsigned long)__builtin_frame_address(0),
			_THIS_IP_);

	unwind(NULL, &state, hyp_save_backtrace_entry, &stacktrace_start);
}
#endif /* !__KVM_NVHE_HYPERVISOR__ */
