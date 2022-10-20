// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2022 - Google LLC
 */

#include <nvhe/pkvm.h>
#include <nvhe/spinlock.h>

#include "../debug-pl011.h"

static void (*__hyp_putc)(char c);

static inline void __hyp_putx4(unsigned int x)
{
	x &= 0xf;
	if (x <= 9)
		x += '0';
	else
		x += ('a' - 0xa);

	__hyp_putc(x);
}

static inline void __hyp_putx4n(unsigned long x, int n)
{
	int i = n >> 2;

	__hyp_putc('0');
	__hyp_putc('x');

	while (i--)
		__hyp_putx4(x >> (4 * i));

	__hyp_putc('\n');
}

static inline bool hyp_serial_enabled(void)
{
	return !!READ_ONCE(__hyp_putc);
}

void hyp_puts(const char *s)
{
	if (!hyp_serial_enabled()) {
		/* fallback to debug-pl011.h */
		___hyp_puts(s);
		return;
	}

	while (*s)
		__hyp_putc(*s++);

	__hyp_putc('\n');
}

void hyp_putx64(u64 x)
{
	if (hyp_serial_enabled())
		__hyp_putx4n(x, 64);
	else
		/* fallback to debug-pl011.h */
		___hyp_putx64(x);
}

void hyp_putc(char c)
{
	if (hyp_serial_enabled())
		__hyp_putc(c);
	else
		/* fallback to debug-pl011.h */
		___hyp_putc(c);
}

int __pkvm_register_serial_driver(void (*hyp_putc_cb)(char))
{
	static DEFINE_HYP_SPINLOCK(lock);
	int ret = 0;

	hyp_spin_lock(&lock);
	if (!hyp_serial_enabled())
		WRITE_ONCE(__hyp_putc, hyp_putc_cb);
	else
		ret = -EBUSY;
	hyp_spin_unlock(&lock);

	return ret;
}
