#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <asm/kvm_pkvm_module.h>

int __kvm_nvhe_pl011_hyp_init(const struct pkvm_module_ops *ops);
void __kvm_nvhe_pl011_hyp_test_hcall(struct kvm_cpu_context *unused);


static int __init pl011_nvhe_init(void)
{
	int ret;

	ret = pkvm_load_el2_module(__kvm_nvhe_pl011_hyp_init);
	if (ret)
		return ret;

	ret = pkvm_register_el2_mod_call(__kvm_nvhe_pl011_hyp_test_hcall);
	if (ret < 0) {
		printk("Failed to register el2 call\n");
	} else {
		printk("Spirit of EL2, are you there? (hcall id=%d)\n", ret);
		pkvm_el2_mod_call(ret);
	}

	return 0;
}
module_init(pl011_nvhe_init);

MODULE_LICENSE("GPL");
