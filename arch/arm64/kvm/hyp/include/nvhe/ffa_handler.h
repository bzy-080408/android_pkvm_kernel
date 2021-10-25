/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 - Google LLC
 * Author: Andrew Walbran <qwandor@google.com>
 */

#include <asm/kvm_host.h>

void ffa_init(void);
bool kvm_host_ffa_handler(struct kvm_cpu_context *host_ctxt);
