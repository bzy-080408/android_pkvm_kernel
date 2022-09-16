#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <asm/kvm_pkvm_module.h>

int __kvm_nvhe_pl011_hyp_init(const struct pkvm_module_ops *ops);

static int __init pl011_nvhe_init(void)
{
	struct pkvm_el2_module mod;
	int ret;

	init_pkvm_module_sections(&mod);
	mod.init = __kvm_nvhe_pl011_hyp_init;

	ret = pkvm_load_el2_module(&mod);
	if (ret)
		return ret;

	printk("boom\n");

	return 0;
}
module_init(pl011_nvhe_init);

MODULE_LICENSE("GPL");
