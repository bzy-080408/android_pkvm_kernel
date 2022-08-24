/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM64_KVM_HYP_NVHE_CLOCK_H
#define __ARM64_KVM_HYP_NVHE_CLOCK_H
#include <linux/types.h>

#ifdef CONFIG_TRACING
u64 hyp_clock(void);
void hyp_clock_setup(u64 epoch_ns, u64 epoch_cyc);
#else
u64 hyp_clock(void) { return 0; }
void hyp_clock_setup(u64 epoch_ns, u64 epoch_cyc) { }
#endif
#endif
