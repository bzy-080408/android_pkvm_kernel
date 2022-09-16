#include <asm/alternative-macros.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pkvm_module.h>
#include <asm/io.h>

// TODO: Kconfig!
#define HYP_PL011_BASE_PHYS	0x09000000
#define HYP_PL011_UARTFR	0x18

#define HYP_PL011_UARTFR_BUSY	3
#define HYP_PL011_UARTFR_FULL	5

static unsigned long uart_addr;

static void pl011_hyp_putc(char c)
{
	unsigned int val;
	void *base = (void *)uart_addr;

	do {
		val = readw(base + HYP_PL011_UARTFR);
	} while (val & (1U << HYP_PL011_UARTFR_FULL));

	writew(c, base);

	do {
		val = readw(base + HYP_PL011_UARTFR);
	} while (val & (1U << HYP_PL011_UARTFR_BUSY));
}

int pl011_hyp_init(const struct pkvm_module_ops *ops)
{
	int ret;

	ret = ops->create_private_mapping(HYP_PL011_BASE_PHYS, PAGE_SIZE,
					  PAGE_HYP_DEVICE, &uart_addr);
	if (ret)
		return ret;

	return ops->register_serial_driver(pl011_hyp_putc);
}
