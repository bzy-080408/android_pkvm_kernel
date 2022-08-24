// SPDX-License-Identifier: GPL-2.0
#include <asm/arch_timer.h>
#include <asm/div64.h>
#include <asm/kvm_hyp.h>

#define MAX_CONVERT_TIME 3600

struct hyp_clock_data hyp_clock_data __ro_after_init;

u64 hyp_clock(void)
{
	u64 cyc = __arch_counter_get_cntpct() - hyp_clock_data.epoch_cyc;
	__uint128_t ns;

	/*
	 * The host kernel can avoid the 64-bits overflow of the multiplication
	 * by updating the epoch value with a timer (see
	 * kernel/time/clocksource.c). The hypervisor doesn't have that option,
	 * so let's do a more costly 128-bits mult here.
	 */
	ns = (__uint128_t)cyc * hyp_clock_data.mult;
	ns >>= hyp_clock_data.shift;

	return (u64)ns + hyp_clock_data.epoch_ns;
}
