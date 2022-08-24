/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM64_KVM_HYP_NVHE_CLOCK_H
#define __ARM64_KVM_HYP_NVHE_CLOCK_H
#include <linux/types.h>

#ifdef CONFIG_TRACING
u64 hyp_clock(void);
#else
u64 hyp_clock(void) { return 0; }
#endif
#endif
