// SPDX-License-Identifier: GPL-2.0
#include <asm/arch_timer.h>
#include <asm/div64.h>

#define MAX_CONVERT_TIME 3600

static struct hyp_clock_data {
	u32 mult;
	u32 shift;
	u64 epoch_ns;
	u64 epoch_cyc;
} hyp_clock_data;

/*
 * This is using epoch values from the host kernel. It intends to synchronize
 * this clock with the host's sched_clock. The downside is we can't trust those
 * value and this shouldn't be used for anything else than debugging things like
 * tracing or printing.
 */
u64 hyp_clock(void)
{
	u64 cyc = __arch_counter_get_cntpct() - hyp_clock_data.epoch_cyc;
	__uint128_t ns;

	ns = (__uint128_t)cyc * hyp_clock_data.mult;
	ns >>= hyp_clock_data.shift;

	return (u64)ns + hyp_clock_data.epoch_ns;
}

/*
 * Mostly borrowed from kernel/time/clocksource.c
 */
void hyp_clock_setup(u64 epoch_ns, u64 epoch_cyc)
{
	unsigned long rate = arch_timer_get_cntfrq();
	u32 shift, shiftacc = 32;
	u64 tmp;

	hyp_clock_data.epoch_ns = epoch_ns;
	hyp_clock_data.epoch_cyc = epoch_cyc;

	if (likely(hyp_clock_data.mult))
		return;
	/*
	 * Calculate the shift factor which is limiting the conversion
	 * range:
	 */
	tmp = ((u64)MAX_CONVERT_TIME * rate) >> 32;
	while (tmp) {
		tmp >>= 1;
		shiftacc--;
	}

	/*
	 * Find the conversion shift/mult pair which has the best
	 * accuracy and fits the maxsec conversion range:
	 */
	for (shift = 32; shift > 0; shift--) {
		tmp = (u64)NSEC_PER_SEC << shift;
		tmp += rate / 2;
		do_div(tmp, rate);
		if ((tmp >> shiftacc) == 0)
			break;
	}

	hyp_clock_data.mult = tmp;
	hyp_clock_data.shift = shift;
}
