// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2020 Google, inc
 * Author: David Brazdil <dbrazdil@google.com>
 */

/* Satistfy dependency of __this_cpu_* routines. */
void __this_cpu_preempt_check(const char __always_unused *op)
{
}
