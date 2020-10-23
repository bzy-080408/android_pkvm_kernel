/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * A stand-alone ticket spinlock implementation, primarily for use by the
 * non-VHE hypervisor code running at EL2.
 *
 * Copyright (C) 2020 Google LLC
 * Author: Will Deacon <will@kernel.org>
 *
 * Heavily based on the implementation removed by c11090474d70 which was:
 * Copyright (C) 2012 ARM Ltd.
 */

#ifndef __KVM_NVHE_HYPERVISOR__
#error "Attempt to include nVHE code outside of EL2 object"
#endif

#ifndef __ARM64_KVM_NVHE_SPINLOCK_H__
#define __ARM64_KVM_NVHE_SPINLOCK_H__

#include <asm/alternative.h>

typedef union nvhe_spinlock {
	u32	__val;
	struct {
#ifdef __AARCH64EB__
		u16 next, owner;
#else
		u16 owner, next;
	};
#endif
} nvhe_spinlock_t;

#define NVHE_SPIN_LOCK_INIT ((nvhe_spinlock_t){ .__val = 0 })

#define nvhe_spin_lock_init(l)		\
do {					\
	*(l) = NVHE_SPIN_LOCK_INIT;	\
} while (0)

static inline void nvhe_spin_lock(nvhe_spinlock_t *lock)
{
	u32 tmp;
	nvhe_spinlock_t lockval, newval;

	asm volatile(
	/* Atomically increment the next ticket. */
	ALTERNATIVE(
	/* LL/SC */
"	prfm	pstl1strm, %3\n"
"1:	ldaxr	%w0, %3\n"
"	add	%w1, %w0, #(1 << 16)\n"
"	stxr	%w2, %w1, %3\n"
"	cbnz	%w2, 1b\n",
	/* LSE atomics */
"	.arch_extension lse\n"
"	mov	%w2, #(1 << 16)\n"
"	ldadda	%w2, %w0, %3\n"
	__nops(3),
	ARM64_HAS_LSE_ATOMICS)

	/* Did we get the lock? */
"	eor	%w1, %w0, %w0, ror #16\n"
"	cbz	%w1, 3f\n"
	/*
	 * No: spin on the owner. Send a local event to avoid missing an
	 * unlock before the exclusive load.
	 */
"	sevl\n"
"2:	wfe\n"
"	ldaxrh	%w2, %4\n"
"	eor	%w1, %w2, %w0, lsr #16\n"
"	cbnz	%w1, 2b\n"
	/* We got the lock. Critical section starts here. */
"3:"
	: "=&r" (lockval), "=&r" (newval), "=&r" (tmp), "+Q" (*lock)
	: "Q" (lock->owner)
	: "memory");
}

static inline void nvhe_spin_unlock(nvhe_spinlock_t *lock)
{
	u64 tmp;

	asm volatile(
	ALTERNATIVE(
	/* LL/SC */
	"	ldrh	%w1, %0\n"
	"	add	%w1, %w1, #1\n"
	"	stlrh	%w1, %0",
	/* LSE atomics */
	"	.arch_extension lse\n"
	"	mov	%w1, #1\n"
	"	staddlh	%w1, %0\n"
	__nops(1),
	ARM64_HAS_LSE_ATOMICS)
	: "=Q" (lock->owner), "=&r" (tmp)
	:
	: "memory");
}

#endif /* __ARM64_KVM_NVHE_SPINLOCK_H__ */
