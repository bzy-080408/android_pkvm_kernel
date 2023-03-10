/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM softlockup
#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_SOFTLOCKUP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_SOFTLOCKUP_H
#include <trace/hooks/vendor_hooks.h>

struct pt_regs;

DECLARE_HOOK(android_vh_watchdog_timer_softlockup,
	TP_PROTO(int duration, struct pt_regs *regs, bool is_panic),
	TP_ARGS(duration, regs, is_panic));

#endif /* _TRACE_HOOK_SOFTLOCKUP_H */
/* This part must be outside protection */
#include <trace/define_trace.h>
