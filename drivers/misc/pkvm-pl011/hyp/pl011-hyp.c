#include <asm/alternative-macros.h>
#include <asm/barrier.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm_module.h>
#include <asm/io.h>

// TODO: Kconfig!
#define HYP_PL011_BASE_PHYS	0x09000000
#define HYP_PL011_UARTFR	0x18
#define HYP_PL011_UARTFR_BUSY	3
#define HYP_PL011_UARTFR_FULL	5

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
	unsigned int val;
	void *base = (void *)uart_addr;

	do {
		val = __hyp_readw(base + HYP_PL011_UARTFR);
	} while (val & (1U << HYP_PL011_UARTFR_FULL));
	__hyp_writew(c, base);
	do {
		val = __hyp_readw(base + HYP_PL011_UARTFR);
	} while (val & (1U << HYP_PL011_UARTFR_BUSY));
}

int pl011_hyp_init(const struct pkvm_module_ops *ops)
{
	int ret;

	uart_addr = ops->create_private_mapping(HYP_PL011_BASE_PHYS, PAGE_SIZE,
					  PAGE_HYP_DEVICE);
	if (IS_ERR((void *)uart_addr))
		return PTR_ERR((void *)uart_addr);

	return ops->register_serial_driver(pl011_hyp_putc);
}
