/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM libsha256
#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_LIBSHA256_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_LIBSHA256_H
#include <linux/tracepoint.h>
#include <trace/hooks/vendor_hooks.h>

DECLARE_HOOK(android_vh_sha256,
	     TP_PROTO(const u8 *data, unsigned int *len, u8 *out),
	     TP_ARGS(data, len, out));

#endif /* _TRACE_HOOK_LIBSHA256_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
