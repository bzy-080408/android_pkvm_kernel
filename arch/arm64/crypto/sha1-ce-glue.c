// SPDX-License-Identifier: GPL-2.0-only
/*
 * sha1-ce-glue.c - SHA-1 secure hash using ARMv8 Crypto Extensions
 *
 * Copyright (C) 2014 - 2017 Linaro Ltd <ard.biesheuvel@linaro.org>
 */

#include <asm/neon.h>
#include <asm/simd.h>
#include <asm/unaligned.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/sha1.h>
#include <crypto/sha1_base.h>
#include <linux/cpufeature.h>
#include <linux/crypto.h>
#include <linux/module.h>

MODULE_DESCRIPTION("SHA1 secure hash using ARMv8 Crypto Extensions");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("sha1");

struct sha1_ce_state {
	struct sha1_state	sst;
	u32			finalize;
};

struct sha1_hmac_ctx {
	u8	ikey[SHA1_BLOCK_SIZE];
	u8	okey[SHA1_BLOCK_SIZE];
};

extern const u32 sha1_ce_offsetof_count;
extern const u32 sha1_ce_offsetof_finalize;

asmlinkage int sha1_ce_transform(struct sha1_ce_state *sst, u8 const *src,
				 int blocks);

static void __sha1_ce_transform(struct sha1_state *sst, u8 const *src,
				int blocks)
{
	while (blocks) {
		int rem;

		kernel_neon_begin();
		rem = sha1_ce_transform(container_of(sst, struct sha1_ce_state,
						     sst), src, blocks);
		kernel_neon_end();
		src += (blocks - rem) * SHA1_BLOCK_SIZE;
		blocks = rem;
	}
}

const u32 sha1_ce_offsetof_count = offsetof(struct sha1_ce_state, sst.count);
const u32 sha1_ce_offsetof_finalize = offsetof(struct sha1_ce_state, finalize);

static int sha1_ce_update(struct shash_desc *desc, const u8 *data,
			  unsigned int len)
{
	struct sha1_ce_state *sctx = shash_desc_ctx(desc);

	if (!crypto_simd_usable())
		return crypto_sha1_update(desc, data, len);

	sctx->finalize = 0;
	sha1_base_do_update(desc, data, len, __sha1_ce_transform);

	return 0;
}

static int sha1_ce_finup(struct shash_desc *desc, const u8 *data,
			 unsigned int len, u8 *out)
{
	struct sha1_ce_state *sctx = shash_desc_ctx(desc);
	bool finalize = !sctx->sst.count && !(len % SHA1_BLOCK_SIZE) && len;

	if (!crypto_simd_usable())
		return crypto_sha1_finup(desc, data, len, out);

	/*
	 * Allow the asm code to perform the finalization if there is no
	 * partial data and the input is a round multiple of the block size.
	 */
	sctx->finalize = finalize;

	sha1_base_do_update(desc, data, len, __sha1_ce_transform);
	if (!finalize)
		sha1_base_do_finalize(desc, __sha1_ce_transform);
	return sha1_base_finish(desc, out);
}

static int sha1_ce_final(struct shash_desc *desc, u8 *out)
{
	struct sha1_ce_state *sctx = shash_desc_ctx(desc);

	if (!crypto_simd_usable())
		return crypto_sha1_finup(desc, NULL, 0, out);

	sctx->finalize = 0;
	sha1_base_do_finalize(desc, __sha1_ce_transform);
	return sha1_base_finish(desc, out);
}

static int sha1_ce_export(struct shash_desc *desc, void *out)
{
	struct sha1_ce_state *sctx = shash_desc_ctx(desc);

	memcpy(out, &sctx->sst, sizeof(struct sha1_state));
	return 0;
}

static int sha1_ce_import(struct shash_desc *desc, const void *in)
{
	struct sha1_ce_state *sctx = shash_desc_ctx(desc);

	memcpy(&sctx->sst, in, sizeof(struct sha1_state));
	sctx->finalize = 0;
	return 0;
}

static int sha1_hmac_ce_setkey(struct crypto_shash *shash, const u8 *inkey,
			       unsigned int keylen)
{
	struct sha1_hmac_ctx *ctx = crypto_shash_ctx(shash);
	u8 dg[SHA1_DIGEST_SIZE] = {};

	memset(ctx->ikey, 0x36, sizeof(ctx->ikey));
	memset(ctx->okey, 0x5c, sizeof(ctx->okey));

	if (keylen > SHA1_BLOCK_SIZE) {
		SHASH_DESC_ON_STACK(desc, dontcare);
		int err;

		desc->tfm = shash;
		sha1_base_init(desc);

		err = sha1_ce_finup(desc, inkey, keylen, dg);
		if (err)
			return err;

		inkey = dg;
		keylen = sizeof(dg);
	}

	crypto_xor(ctx->ikey, inkey, keylen);
	crypto_xor(ctx->okey, inkey, keylen);

	return 0;
}

static int sha1_hmac_ce_init(struct shash_desc *desc)
{
	const struct sha1_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);

	return sha1_base_init(desc) ?:
	       sha1_ce_update(desc, ctx->ikey, sizeof(ctx->ikey));
}

static int sha1_hmac_ce_finup(struct shash_desc *desc, const u8 *data,
			      unsigned int len, u8 *out)
{
	const struct sha1_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);
	SHASH_DESC_ON_STACK(idesc, dontcare);
	u8 dg[SHA1_DIGEST_SIZE];
	int err;

	err = sha1_ce_finup(desc, data, len, dg);
	if (err)
		return err;

	idesc->tfm = desc->tfm;
	sha1_base_init(idesc);

	return sha1_ce_update(idesc, ctx->okey, sizeof(ctx->okey)) ?:
	       sha1_ce_finup(idesc, dg, crypto_shash_digestsize(desc->tfm), out);
}

static int sha1_hmac_ce_final(struct shash_desc *desc, u8 *out)
{
	return sha1_hmac_ce_finup(desc, NULL, 0, out);
}

static struct shash_alg algs[] = { {
	.init			= sha1_base_init,
	.update			= sha1_ce_update,
	.final			= sha1_ce_final,
	.finup			= sha1_ce_finup,
	.import			= sha1_ce_import,
	.export			= sha1_ce_export,
	.descsize		= sizeof(struct sha1_ce_state),
	.statesize		= sizeof(struct sha1_state),
	.digestsize		= SHA1_DIGEST_SIZE,

	.base.cra_name		= "sha1",
	.base.cra_driver_name	= "sha1-ce",
	.base.cra_priority	= 200,
	.base.cra_blocksize	= SHA1_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.init			= sha1_hmac_ce_init,
	.update			= sha1_ce_update,
	.final			= sha1_hmac_ce_final,
	.finup			= sha1_hmac_ce_finup,
	.import			= sha1_ce_import,
	.export			= sha1_ce_export,
	.setkey			= sha1_hmac_ce_setkey,
	.descsize		= sizeof(struct sha1_ce_state),
	.statesize		= sizeof(struct sha1_state),
	.digestsize		= SHA1_DIGEST_SIZE,

	.base.cra_name		= "hmac(sha1)",
	.base.cra_driver_name	= "hmac-sha1-ce",
	.base.cra_priority	= 200,
	.base.cra_blocksize	= SHA1_BLOCK_SIZE,
	.base.cra_ctxsize	= sizeof(struct sha1_hmac_ctx),
	.base.cra_module	= THIS_MODULE,
} };

static int __init sha1_ce_mod_init(void)
{
	return crypto_register_shashes(algs, ARRAY_SIZE(algs));
}

static void __exit sha1_ce_mod_fini(void)
{
	crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}

module_cpu_feature_match(SHA1, sha1_ce_mod_init);
module_exit(sha1_ce_mod_fini);
