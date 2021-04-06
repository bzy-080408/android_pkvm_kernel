// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Linux/arm64 port of the OpenSSL SHA512 implementation for AArch64
 *
 * Copyright (c) 2016 Linaro Ltd. <ard.biesheuvel@linaro.org>
 */

#include <crypto/internal/hash.h>
#include <linux/types.h>
#include <linux/string.h>
#include <crypto/sha2.h>
#include <crypto/sha512_base.h>
#include <asm/neon.h>

#include "sha-hmac.h"

MODULE_DESCRIPTION("SHA-384/SHA-512 secure hash for arm64");
MODULE_AUTHOR("Andy Polyakov <appro@openssl.org>");
MODULE_AUTHOR("Ard Biesheuvel <ard.biesheuvel@linaro.org>");
MODULE_LICENSE("GPL v2");
MODULE_ALIAS_CRYPTO("sha384");
MODULE_ALIAS_CRYPTO("sha512");
MODULE_ALIAS_CRYPTO("hmac(sha384)");
MODULE_ALIAS_CRYPTO("hmac(sha512)");

asmlinkage void sha512_block_data_order(u64 *digest, const void *data,
					unsigned int num_blks);
EXPORT_SYMBOL(sha512_block_data_order);

static void __sha512_block_data_order(struct sha512_state *sst, u8 const *src,
				      int blocks)
{
	sha512_block_data_order(sst->state, src, blocks);
}

static int sha512_update(struct shash_desc *desc, const u8 *data,
			 unsigned int len)
{
	return sha512_base_do_update(desc, data, len,
				     __sha512_block_data_order);
}

static int sha512_finup(struct shash_desc *desc, const u8 *data,
			unsigned int len, u8 *out)
{
	if (len)
		sha512_base_do_update(desc, data, len,
				      __sha512_block_data_order);
	sha512_base_do_finalize(desc, __sha512_block_data_order);

	return sha512_base_finish(desc, out);
}

static int sha512_final(struct shash_desc *desc, u8 *out)
{
	return sha512_finup(desc, NULL, 0, out);
}

int crypto_sha512_hmac_arm64_setkey(struct crypto_shash *shash, const u8 *inkey,
				    unsigned int keylen)
{
	struct sha512_hmac_ctx *ctx = crypto_shash_ctx(shash);
	u8 dg[SHA512_DIGEST_SIZE] = {};

	memset(ctx->ikey, 0x36, sizeof(ctx->ikey));
	memset(ctx->okey, 0x5c, sizeof(ctx->okey));

	if (keylen > SHA512_BLOCK_SIZE) {
		SHASH_DESC_ON_STACK(desc, dontcare);
		int err;

		desc->tfm = shash;
		if (crypto_shash_digestsize(shash) == SHA512_DIGEST_SIZE)
			sha512_base_init(desc);
		else
			sha384_base_init(desc);

		err = sha512_finup(desc, inkey, keylen, dg);
		if (err)
			return err;

		inkey = dg;
		keylen = sizeof(dg);
	}

	crypto_xor(ctx->ikey, inkey, keylen);
	crypto_xor(ctx->okey, inkey, keylen);

	return 0;
}
EXPORT_SYMBOL(crypto_sha512_hmac_arm64_setkey);

static int sha512_hmac_init(struct shash_desc *desc)
{
	const struct sha512_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);

	return sha512_base_init(desc) ?:
	       sha512_update(desc, ctx->ikey, sizeof(ctx->ikey));
}

static int sha384_hmac_init(struct shash_desc *desc)
{
	const struct sha512_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);

	return sha384_base_init(desc) ?:
	       sha512_update(desc, ctx->ikey, sizeof(ctx->ikey));
}

static int sha512_hmac_finup(struct shash_desc *desc, const u8 *data,
			     unsigned int len, u8 *out)
{
	const struct sha512_hmac_ctx *ctx = crypto_shash_ctx(desc->tfm);
	SHASH_DESC_ON_STACK(idesc, dontcare);
	u8 dg[SHA512_DIGEST_SIZE];
	int err;

	err = sha512_finup(desc, data, len, dg);
	if (err)
		return err;

	idesc->tfm = desc->tfm;
	if (crypto_shash_digestsize(desc->tfm) == SHA512_DIGEST_SIZE)
		sha512_base_init(idesc);
	else
		sha384_base_init(idesc);

	return sha512_update(idesc, ctx->okey, sizeof(ctx->okey)) ?:
	       sha512_finup(idesc, dg, crypto_shash_digestsize(desc->tfm), out);
}

static int sha512_hmac_final(struct shash_desc *desc, u8 *out)
{
	return sha512_hmac_finup(desc, NULL, 0, out);
}

static struct shash_alg algs[] = { {
	.digestsize		= SHA512_DIGEST_SIZE,
	.init			= sha512_base_init,
	.update			= sha512_update,
	.final			= sha512_final,
	.finup			= sha512_finup,
	.descsize		= sizeof(struct sha512_state),
	.base.cra_name		= "sha512",
	.base.cra_driver_name	= "sha512-arm64",
	.base.cra_priority	= 150,
	.base.cra_blocksize	= SHA512_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA384_DIGEST_SIZE,
	.init			= sha384_base_init,
	.update			= sha512_update,
	.final			= sha512_final,
	.finup			= sha512_finup,
	.descsize		= sizeof(struct sha512_state),
	.base.cra_name		= "sha384",
	.base.cra_driver_name	= "sha384-arm64",
	.base.cra_priority	= 150,
	.base.cra_blocksize	= SHA384_BLOCK_SIZE,
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA512_DIGEST_SIZE,
	.init			= sha512_hmac_init,
	.update			= sha512_update,
	.final			= sha512_hmac_final,
	.finup			= sha512_hmac_finup,
	.setkey			= crypto_sha512_hmac_arm64_setkey,
	.descsize		= sizeof(struct sha512_state),
	.base.cra_name		= "hmac(sha512)",
	.base.cra_driver_name	= "hmac-sha512-arm64",
	.base.cra_priority	= 150,
	.base.cra_blocksize	= SHA512_BLOCK_SIZE,
	.base.cra_ctxsize	= sizeof(struct sha512_hmac_ctx),
	.base.cra_module	= THIS_MODULE,
}, {
	.digestsize		= SHA384_DIGEST_SIZE,
	.init			= sha384_hmac_init,
	.update			= sha512_update,
	.final			= sha512_hmac_final,
	.finup			= sha512_hmac_finup,
	.setkey			= crypto_sha512_hmac_arm64_setkey,
	.descsize		= sizeof(struct sha512_state),
	.base.cra_name		= "hmac(sha384)",
	.base.cra_driver_name	= "hmac-sha384-arm64",
	.base.cra_priority	= 150,
	.base.cra_blocksize	= SHA384_BLOCK_SIZE,
	.base.cra_ctxsize	= sizeof(struct sha512_hmac_ctx),
	.base.cra_module	= THIS_MODULE,
} };

static int __init sha512_mod_init(void)
{
	return crypto_register_shashes(algs, ARRAY_SIZE(algs));
}

static void __exit sha512_mod_fini(void)
{
	crypto_unregister_shashes(algs, ARRAY_SIZE(algs));
}

module_init(sha512_mod_init);
module_exit(sha512_mod_fini);
