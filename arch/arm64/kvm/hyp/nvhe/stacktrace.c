// SPDX-License-Identifier: GPL-2.0-only
/*
 * Stack unwinder for EL2 nVHE hypervisor.
 *
 * Code mostly copied from the arm64 kernel stack unwinder:
 * arch/arm64/kernel/stacktrace.c
 */

#include <asm/kvm_asm.h>

#include <nvhe/stacktrace.h>

DEFINE_PER_CPU(unsigned long [PAGE_SIZE/sizeof(long)], hyp_overflow_stack)
	__aligned(16);

/*
 * Unwind from one frame record (A) to the next frame record (B).
 *
 * We terminate early if the location of B indicates a malformed chain of frame
 * records (e.g. a cycle), determined based on the location and fp value of A
 * and the location (but not the fp value) of B.
 */
static int notrace hyp_unwind_frame(struct hyp_stackframe *frame)
{
	unsigned long fp = frame->fp;
	struct hyp_stack_info info;


	if (fp & 0x7)
		return -EINVAL;

	if (!hyp_on_accessible_stack(fp, 16, &info))
		return -EINVAL;

	if (test_bit(info.type, frame->stacks_done))
		return -EINVAL;

	/*
	 * As stacks grow downward, any valid record on the same stack must be
	 * at a strictly higher address than the prior record.
	 *
	 * Stacks can nest in the following order:
	 *
	 * HYP -> OVERFLOW
	 *
	 * ... but the nesting itself is strict. Once we transition from one
	 * stack to another, it's never valid to unwind back to that first
	 * stack.
	 */
	if (info.type == frame->prev_type) {
		if (fp <= frame->prev_fp)
			return -EINVAL;
	} else {
		set_bit(frame->prev_type, frame->stacks_done);
	}

	/*
	 * Record this frame record's values and location. The prev_fp and
	 * prev_type are only meaningful to the next hyp_unwind_frame()
	 * invocation.
	 */
	frame->fp = READ_ONCE_NOCHECK(*(unsigned long *)(fp));
	/* PC = LR - 4; All aarch64 instructions are 32-bits in size */
	frame->pc = READ_ONCE_NOCHECK(*(unsigned long *)(fp + 8)) - 4;
	frame->prev_fp = fp;
	frame->prev_type = info.type;

	return 0;
}

/*
 * AArch64 PCS assigns the frame pointer to x29.
 *
 * A simple function prologue looks like this:
 * 	sub	sp, sp, #0x10
 *   	stp	x29, x30, [sp]
 *	mov	x29, sp
 *
 * A simple function epilogue looks like this:
 *	mov	sp, x29
 *	ldp	x29, x30, [sp]
 *	add	sp, sp, #0x10
 */
static void hyp_start_backtrace(struct hyp_stackframe *frame, unsigned long fp,
		     unsigned long pc)
{
	frame->fp = fp;
	frame->pc = pc;

	/*
	 * Prime the first unwind.
	 *
	 * In hyp_unwind_frame() we'll check that the FP points to a valid
	 * stack, which can't be HYP_STACK_TYPE_UNKNOWN, and the first unwind
	 * will be treated as a transition to whichever stack that happens to
	 * be. The prev_fp value won't be used, but we set it to 0 such that
	 * it is definitely not an accessible stack address.
	 */
	bitmap_zero(frame->stacks_done, __NR_HYP_STACK_TYPES);
	frame->prev_fp = 0;
	frame->prev_type = HYP_STACK_TYPE_UNKNOWN;
}

/* Dump the backtrace entry to the panic_info page */
static bool hyp_dump_backtrace_entry(unsigned long pc, int frame_nr, bool check_size)
{
	struct kvm_nvhe_init_params *params = this_cpu_ptr(&kvm_init_params);
	unsigned long *panic_info_page = (unsigned long *)params->panic_info_hyp_va;

	if (check_size && frame_nr == (PAGE_SIZE-1)/sizeof(unsigned long))
		return false;

	*(panic_info_page + frame_nr) = pc;
	return true;
}

void hyp_dump_backtrace(void)
{
	struct hyp_stackframe frame;
	int frame_nr = 0;
	/* Skip the first 2 frames: hyp_dump_backtrace() and its call site */
	int skip = 2;

	hyp_start_backtrace(&frame,
			(unsigned long)__builtin_frame_address(0),
			(unsigned long)hyp_dump_backtrace);

	do {
		if (skip) {
			skip--;
			continue;
		}

		if (!hyp_dump_backtrace_entry(frame.pc, frame_nr, true))
			break;

		frame_nr++;
	} while (!hyp_unwind_frame(&frame));

	/* Add a trailing 0 to delimit the end of the backtrace */
	hyp_dump_backtrace_entry(0, frame_nr, false);
}
