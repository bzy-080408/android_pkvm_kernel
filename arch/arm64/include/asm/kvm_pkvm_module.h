/* SPDX-License-Identifier: GPL-2.0 */

#ifndef __ARM64_KVM_PKVM_MODULE_H__
#define __ARM64_KVM_PKVM_MODULE_H__

#include <asm/kvm_pgtable.h>
#include <linux/export.h>

typedef void (*dyn_hcall_t)(struct kvm_cpu_context *);


//forward declartion for now
struct pkvm_iommu_driver;
struct pkvm_module_ops {
       unsigned long (*create_private_mapping)(phys_addr_t phys, size_t size,
                                               enum kvm_pgtable_prot prot);
       int (*register_hcall)(dyn_hcall_t hfn);
       int (*pkvm_host_donate_hyp)(u64 pfn, u64 nr_pages);
       int (*pkvm_hyp_donate_host)(u64 pfn, u64 nr_pages);
       void* (*memcpy)(void *to, const void *from, size_t count);
       void* (*memset)( void  *dst, int c, size_t count)  ;
       void (*dcache_clean_inval_poc)(unsigned long addr, size_t );
       int (*register_serial_driver)(void (*hyp_putc_cb)(char));
       int (*register_iommu_driver)(struct pkvm_iommu_driver*);
       void (*hyp_puts)(const char *s);
       phys_addr_t (*module_hyp_pa)(phys_addr_t x);
       phys_addr_t (*module_kern_hyp_va)(phys_addr_t x);
 };


struct pkvm_module_section {
	void *start;
	void *end;
};

typedef s32 kvm_nvhe_reloc_t;

struct pkvm_el2_map {
	void *kern_va;
	void *hyp_va;
};

struct pkvm_el2_module {
	struct pkvm_module_section text;
	struct pkvm_module_section bss;
	struct pkvm_module_section rodata;
	struct pkvm_module_section data;
	kvm_nvhe_reloc_t *relocs;
	unsigned int nr_relocs;
	struct pkvm_el2_map el2_map;
	int (*init)(const struct pkvm_module_ops *ops);
};

#ifdef MODULE
int __pkvm_load_el2_module(struct pkvm_el2_module *mod, struct module *this);

/**
 * pkvm_load_el2_module: blah
 *
 * function_nocfi() does not work with function pointers, hence the macro in
 * lieu of a function.
 */
#define pkvm_load_el2_module(init_fn)					\
({									\
	extern char __kvm_nvhe___hypmod_text_start[];			\
	extern char __kvm_nvhe___hypmod_text_end[];			\
	extern char __kvm_nvhe___hypmod_bss_start[];			\
	extern char __kvm_nvhe___hypmod_bss_end[];			\
	extern char __kvm_nvhe___hypmod_rodata_start[];			\
	extern char __kvm_nvhe___hypmod_rodata_end[];			\
	extern char __kvm_nvhe___hypmod_data_start[];			\
	extern char __kvm_nvhe___hypmod_data_end[];			\
	extern char __kvm_nvhe___hyprel_start[];			\
	extern char __kvm_nvhe___hyprel_end[];				\
	struct pkvm_el2_module mod;					\
									\
	mod.text.start		= __kvm_nvhe___hypmod_text_start;	\
	mod.text.end		= __kvm_nvhe___hypmod_text_end;		\
	mod.bss.start		= __kvm_nvhe___hypmod_bss_start;	\
	mod.bss.end		= __kvm_nvhe___hypmod_bss_end;		\
	mod.rodata.start	= __kvm_nvhe___hypmod_rodata_start;	\
	mod.rodata.end		= __kvm_nvhe___hypmod_rodata_end;	\
	mod.data.start		= __kvm_nvhe___hypmod_data_start;	\
	mod.data.end		= __kvm_nvhe___hypmod_data_end;		\
	mod.relocs		= (kvm_nvhe_reloc_t *)__kvm_nvhe___hyprel_start; \
	mod.nr_relocs		= (__kvm_nvhe___hyprel_end - __kvm_nvhe___hyprel_start) / \
				  sizeof(*mod.relocs); \
	mod.init = function_nocfi(init_fn);				\
									\
	__pkvm_load_el2_module(&mod, THIS_MODULE);			\
})

int __pkvm_register_el2_call(struct pkvm_el2_map *map, dyn_hcall_t hfn);
static __always_inline int
pkvm_register_el2_mod_call(struct pkvm_el2_module *mod, dyn_hcall_t hfn)
{
	return __pkvm_register_el2_call(&mod->el2_map, hfn);
}

static inline void init_pkvm_module_sections(struct pkvm_el2_module *mod)
{
	extern char __kvm_nvhe___hypmod_text_start[];
	extern char __kvm_nvhe___hypmod_text_end[];
	extern char __kvm_nvhe___hypmod_bss_start[];
	extern char __kvm_nvhe___hypmod_bss_end[];
	extern char __kvm_nvhe___hypmod_rodata_start[];
	extern char __kvm_nvhe___hypmod_rodata_end[];
	extern char __kvm_nvhe___hypmod_data_start[];
	extern char __kvm_nvhe___hypmod_data_end[];
	extern char __kvm_nvhe___hyprel_start[];
	extern char __kvm_nvhe___hyprel_end[];

	mod->text.start		= __kvm_nvhe___hypmod_text_start;
	mod->text.end		= __kvm_nvhe___hypmod_text_end;
	mod->bss.start		= __kvm_nvhe___hypmod_bss_start;
	mod->bss.end		= __kvm_nvhe___hypmod_bss_end;
	mod->rodata.start	= __kvm_nvhe___hypmod_rodata_start;
	mod->rodata.end		= __kvm_nvhe___hypmod_rodata_end;
	mod->data.start		= __kvm_nvhe___hypmod_data_start;
	mod->data.end		= __kvm_nvhe___hypmod_data_end;
	mod->relocs		= (kvm_nvhe_reloc_t *)__kvm_nvhe___hyprel_start;
	mod->nr_relocs		= (__kvm_nvhe___hyprel_end - __kvm_nvhe___hyprel_start) /
				  sizeof(*mod->relocs);
}

#define pkvm_el2_mod_call(id, ...)					\
	({								\
		struct arm_smccc_res res;				\
									\
		arm_smccc_1_1_hvc(KVM_HOST_SMCCC_ID(id),		\
				  ##__VA_ARGS__, &res);			\
		WARN_ON(res.a0 != SMCCC_RET_SUCCESS);			\
									\
		res.a1;							\
	})
#endif
#endif
