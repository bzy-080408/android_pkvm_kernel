/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

#ifndef __ARM64_KVM_NVHE_PKVM_H__
#define __ARM64_KVM_NVHE_PKVM_H__

#include <asm/kvm_host.h>

void __pkvm_vcpu_init_traps(struct kvm_vcpu *vcpu);

#endif /* __ARM64_KVM_NVHE_PKVM_H__ */
