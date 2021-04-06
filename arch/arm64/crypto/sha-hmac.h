/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 - Google Inc
 * Author: Ard Biesheuvel <ardb@google.com>
 */

#include <linux/types.h>
#include <crypto/sha2.h>

struct sha256_hmac_ctx {
	u8	ikey[SHA256_BLOCK_SIZE];
	u8	okey[SHA256_BLOCK_SIZE];
};

struct sha512_hmac_ctx {
	u8	ikey[SHA512_BLOCK_SIZE];
	u8	okey[SHA512_BLOCK_SIZE];
};

int crypto_sha256_hmac_arm64_setkey(struct crypto_shash *shash, const u8 *inkey,
				    unsigned int keylen);

int crypto_sha512_hmac_arm64_setkey(struct crypto_shash *shash, const u8 *inkey,
				    unsigned int keylen);
