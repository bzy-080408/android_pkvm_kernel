#include <asm/alternative-macros.h>
#include <asm/barrier.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm_module.h>
#include <asm/io.h>

// TODO: Kconfig!
#define HYP_PL011_BASE_PHYS	0x10A00000
#define HYP_PL011_UARTFR	0x10
#define HYP_PL011_UARTTX	0x20

#define HYP_PL011_UARTFR_BUSY	2
#define HYP_PL011_UARTFR_FULL	(BIT(1) | BIT(2))

static unsigned long uart_addr;

static inline unsigned int __hyp_readw(void *ioaddr)
{
	unsigned int val;
	asm volatile("ldr %w0, [%1]" : "=r" (val) : "r" (ioaddr));
	return val;
}
static inline void __hyp_writew(unsigned int val, void *ioaddr)
{
	asm volatile("str %w0, [%1]" : : "r" (val), "r" (ioaddr));
}

static void pl011_hyp_putc(char c)
{
	void *base = (void *)uart_addr;

	while (!(__hyp_readw(base + HYP_PL011_UARTFR) & HYP_PL011_UARTFR_FULL)) { }
	dmb(sy);
	__hyp_writew(c, base + HYP_PL011_UARTTX);
	dmb(sy);
}

int pl011_hyp_init(const struct pkvm_module_ops *ops)
{
	uart_addr = ops->create_private_mapping(HYP_PL011_BASE_PHYS, PAGE_SIZE,
						PAGE_HYP_DEVICE);
	if (!uart_addr)
		return -EINVAL;

	return ops->register_serial_driver(pl011_hyp_putc);
}
