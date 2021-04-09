// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux/arm64 port of the OpenSSL SHA256 implementation for AArch64
 *
 * Copyright (c) 2016 Linaro Ltd. <ard.biesheuvel@linaro.org>
 */

#include <asm/hwcap.h>
#include <asm/neon.h>
#include <asm/simd.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/simd.h>
#include <crypto/sha2.h>
#include <crypto/sha256_base.h>
#include <linux/types.h>
#include <linux/string.h>

#include "sha-hmac.h"

MODULE_DESCRIPTION("SHA-224/SHA-256 secure hash for arm64");
MODULE_AUTHOR("Andy Polyakov <appro@openssl.org>");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("sha224");
MODULE_ALIAS_CRYPTO("sha256");
MODULE_ALIAS_CRYPTO("hmac(sha224)");
MODULE_ALIAS_CRYPTO("hmac(sha256)");

asmlinkage void sha256_block_data_order(u32 *digest, const void *data,
					unsigned int num_blks);
EXPORT_SYMBOL(sha256_block_data_order);

static void __sha256_block_data_order(struct sha256_state *sst, u8 const *src,
				      int blocks)
{
	sha256_block_data_order(sst->state, src, blocks);
}

asmlinkage void sha256_block_neon(u32 *digest, const void *data,
				  unsigned int num_blks);

static void __sha256_block_neon(struct sha256_state *sst, u8 const *src,
				int blocks)
{
	sha256_block_neon(sst->state, src, blocks);
}

static int crypto_sha256_arm64_update(struct shash_desc *desc, const u8 *data,
				      unsigned int len)
{
	return sha256_base_do_update(desc, data, len,
				     __sha256_block_data_order);
}

static int crypto_sha256_arm64_finup(struct shash_desc *desc, const u8 *data,
				     unsigned int len, u8 *out)
{
	if (len)
		sha256_base_do_update(desc, data, len,
				      __sha256_block_data_order);
	sha256_base_do_finalize(desc, __sha256_block_data_order);

	return sha256_base_finish(desc, out);
}

static int crypto_sha256_arm64_final(struct shash_desc *desc, u8 *out)
{
	return crypto_sha256_arm64_finup(desc, NULL, 0, out);
}

int crypto_sha256_hmac_arm64_setkey(struct crypto_shash *shash, const u8 *inkey,
				    unsigned int keylen)
{
	struct sha256_hmac_ctx *ctx = crypto_shash_ctx(shash);
	u8 dg[SHA256_DIGEST_SIZE];

	memset(ctx->ikey, 0x36, sizeof(ctx->ikey));
	memset(ctx->okey, 0x5c, sizeof(ctx->okey));

	if (keylen > SHA256_BLOCK_SIZE) {
		SHASH_DESC_ON_STACK(desc, dontcare);
		int err;

		desc->tfm = shash;
		if (crypto_shash_digestsize(shash) == SHA256_DIGEST_SIZE)
			sha256_base_init(desc);
		else
			sha224_base_init(desc);

		err = crypto_sha256_arm64_finup(desc, inkey, keylen, dg);
		if (err)
			return err;

		inkey = dg;
		keylen = crypto_shash_digestsize(shash);
	}

	crypto_xor(ctx->ikey, inkey, keylen);
	crypto_xor(ctx->okey, inkey, keylen);

	return 0;
}
EXPORT_SYMBOL(crypto_sha256_hmac_arm64_setkey);

static int sha256_hmac_init(struct shash_desc *desc)
{
	const struct sha256_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);

	return sha256_base_init(desc) ?:
	       crypto_sha256_arm64_update(desc, ctx->ikey, sizeof(ctx->ikey));
}

static int sha224_hmac_init(struct shash_desc *desc)
{
	const struct sha256_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);

	return sha224_base_init(desc) ?:
	       crypto_sha256_arm64_update(desc, ctx->ikey, sizeof(ctx->ikey));
}

static int sha256_hmac_finup(struct shash_desc *desc, const u8 *data,
			     unsigned int len, u8 *out)
{
	const struct sha256_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);
	SHASH_DESC_ON_STACK(idesc, dontcare);
	u8 dg[SHA256_DIGEST_SIZE];
	int err;

	err = crypto_sha256_arm64_finup(desc, data, len, dg);
	if (err)
		return err;

	idesc->tfm = desc->tfm;
	if (crypto_shash_digestsize(desc->tfm) == SHA256_DIGEST_SIZE)
		sha256_base_init(idesc);
	else
		sha224_base_init(idesc);

	return crypto_sha256_arm64_update(idesc, ctx->okey, sizeof(ctx->okey)) ?:
	       crypto_sha256_arm64_finup(idesc, dg,
					 crypto_shash_digestsize(desc->tfm), out);
}

static int sha256_hmac_final(struct shash_desc *desc, u8 *out)
{
	return sha256_hmac_finup(desc, NULL, 0, out);
}

static struct shash_alg algs[] = { {
	.digestsize		= SHA256_DIGEST_SIZE,
	.init			= sha256_base_init,
	.update			= crypto_sha256_arm64_update,
	.final			= crypto_sha256_arm64_final,
	.finup			= crypto_sha256_arm64_finup,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "sha256",
	.base.cra_driver_name	= "sha256-arm64",
	.base.cra_priority	= 125,
	.base.cra_blocksize	= SHA256_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA224_DIGEST_SIZE,
	.init			= sha224_base_init,
	.update			= crypto_sha256_arm64_update,
	.final			= crypto_sha256_arm64_final,
	.finup			= crypto_sha256_arm64_finup,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "sha224",
	.base.cra_driver_name	= "sha224-arm64",
	.base.cra_priority	= 125,
	.base.cra_blocksize	= SHA224_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA256_DIGEST_SIZE,
	.init			= sha256_hmac_init,
	.update			= crypto_sha256_arm64_update,
	.final			= sha256_hmac_final,
	.finup			= sha256_hmac_finup,
	.setkey			= crypto_sha256_hmac_arm64_setkey,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "hmac(sha256)",
	.base.cra_driver_name	= "hmac-sha256-arm64",
	.base.cra_priority	= 125,
	.base.cra_blocksize	= SHA256_BLOCK_SIZE,
	.base.cra_ctxsize	= sizeof(struct sha256_hmac_ctx),
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA224_DIGEST_SIZE,
	.init			= sha224_hmac_init,
	.update			= crypto_sha256_arm64_update,
	.final			= sha256_hmac_final,
	.finup			= sha256_hmac_finup,
	.setkey			= crypto_sha256_hmac_arm64_setkey,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "hmac(sha224)",
	.base.cra_driver_name	= "hmac-sha224-arm64",
	.base.cra_priority	= 125,
	.base.cra_blocksize	= SHA224_BLOCK_SIZE,
	.base.cra_ctxsize	= sizeof(struct sha256_hmac_ctx),
	.base.cra_module	= THIS_MODULE,
} };

static int sha256_update_neon(struct shash_desc *desc, const u8 *data,
			      unsigned int len)
{
	struct sha256_state *sctx = shash_desc_ctx(desc);

	if (!crypto_simd_usable())
		return sha256_base_do_update(desc, data, len,
				__sha256_block_data_order);

	while (len > 0) {
		unsigned int chunk = len;

		/*
		 * Don't hog the CPU for the entire time it takes to process all
		 * input when running on a preemptible kernel, but process the
		 * data block by block instead.
		 */
		if (IS_ENABLED(CONFIG_PREEMPTION) &&
		    chunk + sctx->count % SHA256_BLOCK_SIZE > SHA256_BLOCK_SIZE)
			chunk = SHA256_BLOCK_SIZE -
				sctx->count % SHA256_BLOCK_SIZE;

		kernel_neon_begin();
		sha256_base_do_update(desc, data, chunk, __sha256_block_neon);
		kernel_neon_end();
		data += chunk;
		len -= chunk;
	}
	return 0;
}

static int sha256_finup_neon(struct shash_desc *desc, const u8 *data,
			     unsigned int len, u8 *out)
{
	if (!crypto_simd_usable()) {
		if (len)
			sha256_base_do_update(desc, data, len,
				__sha256_block_data_order);
		sha256_base_do_finalize(desc, __sha256_block_data_order);
	} else {
		if (len)
			sha256_update_neon(desc, data, len);
		kernel_neon_begin();
		sha256_base_do_finalize(desc, __sha256_block_neon);
		kernel_neon_end();
	}
	return sha256_base_finish(desc, out);
}

static int sha256_final_neon(struct shash_desc *desc, u8 *out)
{
	return sha256_finup_neon(desc, NULL, 0, out);
}

static int sha256_hmac_init_neon(struct shash_desc *desc)
{
	const struct sha256_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);

	return sha256_base_init(desc) ?:
	       sha256_update_neon(desc, ctx->ikey, sizeof(ctx->ikey));
}

static int sha224_hmac_init_neon(struct shash_desc *desc)
{
	const struct sha256_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);

	return sha224_base_init(desc) ?:
	       sha256_update_neon(desc, ctx->ikey, sizeof(ctx->ikey));
}

static int sha256_hmac_finup_neon(struct shash_desc *desc, const u8 *data,
				  unsigned int len, u8 *out)
{
	const struct sha256_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);
	SHASH_DESC_ON_STACK(idesc, dontcare);
	u8 dg[SHA256_DIGEST_SIZE];
	int err;

	err = sha256_finup_neon(desc, data, len, dg);
	if (err)
		return err;

	idesc->tfm = desc->tfm;
	if (crypto_shash_digestsize(desc->tfm) == SHA256_DIGEST_SIZE)
		sha256_base_init(idesc);
	else
		sha224_base_init(idesc);

	return sha256_update_neon(idesc, ctx->okey, sizeof(ctx->okey)) ?:
	       sha256_finup_neon(idesc, dg, crypto_shash_digestsize(desc->tfm), out);
}

static int sha256_hmac_final_neon(struct shash_desc *desc, u8 *out)
{
	return sha256_hmac_finup_neon(desc, NULL, 0, out);
}

static struct shash_alg neon_algs[] = { {
	.digestsize		= SHA256_DIGEST_SIZE,
	.init			= sha256_base_init,
	.update			= sha256_update_neon,
	.final			= sha256_final_neon,
	.finup			= sha256_finup_neon,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "sha256",
	.base.cra_driver_name	= "sha256-arm64-neon",
	.base.cra_priority	= 150,
	.base.cra_blocksize	= SHA256_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA224_DIGEST_SIZE,
	.init			= sha224_base_init,
	.update			= sha256_update_neon,
	.final			= sha256_final_neon,
	.finup			= sha256_finup_neon,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "sha224",
	.base.cra_driver_name	= "sha224-arm64-neon",
	.base.cra_priority	= 150,
	.base.cra_blocksize	= SHA224_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA256_DIGEST_SIZE,
	.init			= sha256_hmac_init_neon,
	.update			= sha256_update_neon,
	.final			= sha256_hmac_final_neon,
	.finup			= sha256_hmac_finup_neon,
	.setkey			= crypto_sha256_hmac_arm64_setkey,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "hmac(sha256)",
	.base.cra_driver_name	= "hmac-sha256-arm64",
	.base.cra_priority	= 125,
	.base.cra_blocksize	= SHA256_BLOCK_SIZE,
	.base.cra_ctxsize	= sizeof(struct sha256_hmac_ctx),
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA224_DIGEST_SIZE,
	.init			= sha224_hmac_init_neon,
	.update			= sha256_update_neon,
	.final			= sha256_hmac_final_neon,
	.finup			= sha256_hmac_finup_neon,
	.setkey			= crypto_sha256_hmac_arm64_setkey,
	.descsize		= sizeof(struct sha256_state),
	.base.cra_name		= "hmac(sha224)",
	.base.cra_driver_name	= "hmac-sha224-arm64",
	.base.cra_priority	= 125,
	.base.cra_blocksize	= SHA224_BLOCK_SIZE,
	.base.cra_ctxsize	= sizeof(struct sha256_hmac_ctx),
	.base.cra_module	= THIS_MODULE,
} };

static int __init sha256_mod_init(void)
{
	int ret = crypto_register_shashes(algs, ARRAY_SIZE(algs));
	if (ret)
		return ret;

	if (cpu_have_named_feature(ASIMD)) {
		ret = crypto_register_shashes(neon_algs, ARRAY_SIZE(neon_algs));
		if (ret)
			crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
	}
	return ret;
}

static void __exit sha256_mod_fini(void)
{
	if (cpu_have_named_feature(ASIMD))
		crypto_unregister_shashes(neon_algs, ARRAY_SIZE(neon_algs));
	crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}

module_init(sha256_mod_init);
module_exit(sha256_mod_fini);
