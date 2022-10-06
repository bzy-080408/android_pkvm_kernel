/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Stand-alone header for basic debug output on the PL011 UART.  To use it,
 * ensure that CONFIG_KVM_ARM_HYP_DEBUG_UART is enabled and that
 * CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR is the physical address of the PL011
 * UART that you want to use. Then just include this header and try not to
 * vomit at the state of the macros and functions it provides.
 *
 * The C functions only work when the MMU is enabled, but the assembly macros
 * should work pretty much everywhere.
 *
 * It's slow and racy, but you'll be fine. Patches unwelcome.
 */

#ifndef ___ARM64_KVM_HYP_DEBUG_PL011_H___
#define ___ARM64_KVM_HYP_DEBUG_PL011_H___

#ifdef CONFIG_KVM_ARM_HYP_DEBUG_UART

#define HYP_PL011_BASE_PHYS	CONFIG_KVM_ARM_HYP_DEBUG_UART_ADDR
#define HYP_PL011_UARTFR	0x10
#define HYP_PL011_UARTTX	0x20
#define HYP_PL011_UARTFR_BUSY	2
#define HYP_PL011_UARTFR_FULL	(BIT(1) | BIT(2))

#ifdef ___ASSEMBLY___

.macro hyp_pl011_base, tmp
	mrs		\tmp, sctlr_el2
	tbz		\tmp, #0, 9990f
	isb

alternative_cb kvm_hyp_debug_uart_set_basep
	movz		\tmp, #0
	movk		\tmp, #0, lsl #16
	movk		\tmp, #0, lsl #32
	movk		\tmp, #0, lsl #48
alternative_cb_end

	kern_hyp_va	\tmp
	ldr		\tmp, [\tmp]
	b		9991f
9990:	mov		\tmp, HYP_PL011_BASE_PHYS
9991:
.endm

/*
 * 'c' is a W register containing the character to transmit. Preserved.
 * 'tmpnr' is the number of another scratch register. Clobbered.
 */
.macro ___hyp_putc, c, tmpnr
9992:	hyp_pl011_base	x\tmpnr
	ldr		w\tmpnr, [x\tmpnr, HYP_PL011_UARTFR]
	tbnz		w\tmpnr, HYP_PL011_UARTFR_FULL, 9992b
	dmb		sy
	hyp_pl011_base	x\tmpnr
	str		\c, [x\tmpnr, #HYP_PL011_UARTTX]
	dmb		sy
.endm

/*
 * 's' is an X register containing the address of the string to print.
 * 'tmpnr1' and  'tmpnr2' are numbers of other scratch registers.
 * All three registers clobbered.
 *
 * The string must be mapped, so it's best to use a combination of '.ascii'
 * and PC-relative addressing (i.e. an ADR instruction)
 */
.macro ___hyp_puts, s, tmpnr1, tmpnr2
9993:	ldrb		w\tmpnr1, [\s]
	cbz		w\tmpnr1, 9993f
	___hyp_putc	w\tmpnr1, \tmpnr2
	add		\s, \s, #1
	b		9993b
9993:	mov		w\tmpnr1, '\n'
	___hyp_putc	w\tmpnr1, \tmpnr2
.endm

.macro ___hyp_putx4, xnr, tmpnr
	bic		x\xnr, x\xnr, #0xfffffff0
	sub		w\tmpnr, w\xnr, #10
	tbnz		w\tmpnr, #31, 9994f
	add		x\xnr, x\xnr, #0x27
9994:	add		x\xnr, x\xnr, #0x30
	___hyp_putc	w\xnr, \tmpnr
.endm

/*
 * 'x' is an X register containing a value to printed in hex. Preserved.
 * 'tmpnr1' and  'tmpnr2' are numbers of other scratch registers. Clobbered.
 */
.macro ___hyp_putx64, x, tmpnr1, tmpnr2
	mov		w\tmpnr1, '0'
	___hyp_putc	w\tmpnr1, \tmpnr2
	mov		w\tmpnr1, 'x'
	___hyp_putc	w\tmpnr1, \tmpnr2
	movz		x\tmpnr1, #15, lsl #32
9995:	bfxil		x\tmpnr1, \x, #60, #4
	ror		\x, \x, #60
	___hyp_putx4	\tmpnr1, \tmpnr2
	ror		x\tmpnr1, x\tmpnr1, #32
	cbz		w\tmpnr1, 9995f
	sub		x\tmpnr1, x\tmpnr1, #1
	ror		x\tmpnr1, x\tmpnr1, #32
	b		9995b
9995:	mov		w\tmpnr1, '\n'
	___hyp_putc	w\tmpnr1, \tmpnr2
.endm

#else

static inline void *___hyp_pl011_base(void)
{
	unsigned long ioaddr;

	asm volatile(ALTERNATIVE_CB(
		"movz	%0, #0\n"
		"movk	%0, #0, lsl #16\n"
		"movk	%0, #0, lsl #32\n"
		"movk	%0, #0, lsl #48",
		kvm_hyp_debug_uart_set_basep)
		: "=r" (ioaddr));

	return *((void **)kern_hyp_va(ioaddr));
}

static inline unsigned int ___hyp_readw(void *ioaddr)
{
	unsigned int val;
	asm volatile("ldr %w0, [%1]" : "=r" (val) : "r" (ioaddr));
	return val;
}

static inline void ___hyp_writew(unsigned int val, void *ioaddr)
{
	asm volatile("str %w0, [%1]" : : "r" (val), "r" (ioaddr));
}

static inline void ___hyp_putc(char c)
{
	void *base = ___hyp_pl011_base();

	while (!(___hyp_readw(base + HYP_PL011_UARTFR) & HYP_PL011_UARTFR_FULL)) {}
	dmb(sy);
	___hyp_writew(c, base + HYP_PL011_UARTTX);
	dmb(sy);
}

/*
 * Caller needs to ensure string is mapped. If it lives in .rodata, you should
 * be good as long as we're using PC-relative addressing (probably true).
 */
static inline void ___hyp_puts(const char *s)
{
	while (*s)
		___hyp_putc(*s++);
	___hyp_putc('\n');
	___hyp_putc('\r');
}

static inline void ___hyp_putx4(unsigned int x)
{
	x &= 0xf;
	if (x <= 9)
		x += '0';
	else
		x += ('a' - 0xa);
	___hyp_putc(x);
}

static inline void ___hyp_putx4n(unsigned long x, int n)
{
	int i = n >> 2;

	___hyp_putc('0');
	___hyp_putc('x');

	while (i--)
		___hyp_putx4(x >> (4 * i));

	___hyp_putc('\n');
	___hyp_putc('\r');
}

static inline void ___hyp_putx32(unsigned int x)
{
	___hyp_putx4n(x, 32);
}

static inline void ___hyp_putx64(unsigned long x)
{
	___hyp_putx4n(x, 64);
}

#endif

#else

#warning "Please don't include debug-pl011.h if you're not debugging"

#ifdef ___ASSEMBLY___

.macro ___hyp_putc, c, tmpnr
.endm

.macro ___hyp_puts, s, tmpnr1, tmpnr2
.endm

.macro ___hyp_putx64, x, tmpnr1, tmpnr2
.endm

#else

static inline void ___hyp_putc(char c) { }
static inline void ___hyp_puts(const char *s) { }
static inline void ___hyp_putx32(unsigned int x) { }
static inline void ___hyp_putx64(unsigned long x) { }

#endif

#endif	/* CONFIG_KVM_ARM_HYP_DEBUG_UART */
#endif	/* ___ARM64_KVM_HYP_DEBUG_PL011_H___ */
