/* SPDX-License-Identifier: GPL-2.0 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM libaes
#define TRACE_INCLUDE_PATH trace/hooks

#if !defined(_TRACE_HOOK_LIBAES_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_HOOK_LIBAES_H
#include <linux/tracepoint.h>
#include <trace/hooks/vendor_hooks.h>

struct crypto_aes_ctx;

DECLARE_HOOK(android_vh_aes_expandkey,
	     TP_PROTO(struct crypto_aes_ctx *ctx,
		      const u8 *in_key,
		      unsigned int key_len,
		      int *err),
	     TP_ARGS(ctx, in_key, key_len, err));

DECLARE_HOOK(android_vh_aes_encrypt,
	     TP_PROTO(const struct crypto_aes_ctx *ctx,
		      u8 *out,
		      const u8 *in,
		      int *ret),
	     TP_ARGS(ctx, out, in, ret));

DECLARE_HOOK(android_vh_aes_decrypt,
	     TP_PROTO(const struct crypto_aes_ctx *ctx,
		      u8 *out,
		      const u8 *in,
		      int *ret),
	     TP_ARGS(ctx, out, in, ret));

#endif /* _TRACE_HOOK_LIBAES_H */

/* This part must be outside protection */
#include <trace/define_trace.h>
