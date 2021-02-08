/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 *
 * AArch64 exception vector table
 * Handles exceptions from current EL with SPx, and calls the optional callback
 * function registered by aarch64_guest_exception_setup.
 */

#define FRAME_SIZE (8 * 22)

/* Save volatile registers onto the stack. */
.macro save_regs
	stp x0,  x1,  [sp, #-FRAME_SIZE]!
	stp x2,  x3,  [sp, #8 * 2]
	stp x4,  x5,  [sp, #8 * 4]
	stp x6,  x7,  [sp, #8 * 6]
	stp x8,  x9,  [sp, #8 * 8]
	stp x10, x11, [sp, #8 * 10]
	stp x12, x13, [sp, #8 * 12]
	stp x14, x15, [sp, #8 * 14]
	stp x16, x17, [sp, #8 * 16]
	stp x18, x29, [sp, #8 * 18]
        str x30,      [sp, #8 * 20]
.endm

/* Restore volatile registers from the stack. */
.macro restore_regs
        ldr x30,      [sp, #8 * 20]
	ldp x18, x29, [sp, #8 * 18]
	ldp x16, x17, [sp, #8 * 16]
	ldp x14, x15, [sp, #8 * 14]
	ldp x12, x13, [sp, #8 * 12]
	ldp x10, x11, [sp, #8 * 10]
        ldp  x8,  x9, [sp, #8 * 8]
	ldp  x6,  x7, [sp, #8 * 6]
	ldp  x4,  x5, [sp, #8 * 4]
	ldp  x2,  x3, [sp, #8 * 2]
	ldp  x0,  x1, [sp], #FRAME_SIZE
.endm

.section .text.vector_table
.global vector_table
.balign 0x800
vector_table:
cur_sp0_sync:
	b .

.balign 0x80
cur_sp0_irq:
	b .

.balign 0x80
cur_sp0_fiq:
	b .

.balign 0x80
cur_sp0_serr:
	b .

.balign 0x80
cur_spx_sync:
	save_regs
	bl handle_exception
	restore_regs
        eret

.balign 0x80
cur_spx_irq:
	b .

.balign 0x80
cur_spx_fiq:
	b .

.balign 0x80
cur_spx_serr:
	b .

.balign 0x80
lower_64_sync:
	b .

.balign 0x80
lower_64_irq:
	b .

.balign 0x80
lower_64_fiq:
	b .

.balign 0x80
lower_64_serr:
	b .

.balign 0x80
lower_32_sync:
	b .

.balign 0x80
lower_32_irq:
	b .

.balign 0x80
lower_32_fiq:
	b .

.balign 0x80
lower_32_serr:
	b .
