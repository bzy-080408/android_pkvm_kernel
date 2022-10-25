#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

#include <asm/kvm_pkvm_module.h>

/* Hypervisor module symbols */
int __kvm_nvhe_hyp_init(const struct pkvm_module_ops *ops);
extern phys_addr_t __kvm_nvhe_text_start;
extern phys_addr_t __kvm_nvhe_text_end;

static int __init text_prot_init(void)
{
	unsigned long token;

	kvm_get_kernel_pa(&__kvm_nvhe_text_start, &__kvm_nvhe_text_end);

	return pkvm_load_el2_module(__kvm_nvhe_hyp_init, &token);
}
module_init(text_prot_init);

MODULE_LICENSE("GPL");
