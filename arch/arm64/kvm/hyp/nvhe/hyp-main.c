// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 - Google Inc
 * Author: Andrew Scull <ascull@google.com>
 */

#include <asm/kvm_hyp.h>

DEFINE_PER_CPU(struct kvm_nvhe_hyp_params, kvm_nvhe_hyp_params);

void kvm_hyp_main(struct kvm_nvhe_hyp_params *params)
{
}
