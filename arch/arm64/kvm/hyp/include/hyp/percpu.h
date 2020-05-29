// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: David Brazdil <dbrazdil@google.com>
 */

#ifndef __ARM64_KVM_HYP_PERCPU_H__
#define __ARM64_KVM_HYP_PERCPU_H__

#if !defined(__KVM_VHE_HYPERVISOR__) && !defined(__KVM_NVHE_HYPERVISOR__)
#error "Attempted to include header outside of hyp code"
#endif

#ifndef __ASM_PERCPU_H
#include <asm/percpu.h>
#else
#error "<asm/percpu.h> was included before hyp header"
#endif

/* Redefine macros for nVHE to avoid dependency on __this_cpu_preempt_check. */
#ifdef __KVM_NVHE_HYPERVISOR
#undef	this_cpu_ptr
#define	this_cpu_ptr		arch_raw_cpu_ptr
#undef	__this_cpu_read
#define	__this_cpu_read		raw_cpu_read
#undef	__this_cpu_write
#define	__this_cpu_write	raw_cpu_write
#endif /* __KVM_NVHE_HYPERVISOR */

#endif /* __ARM64_KVM_HYP_PERCPU_H__ */
