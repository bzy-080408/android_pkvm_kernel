#ifndef __KVM_HYP_SETUP_H
#define __KVM_HYP_SETUP_H
#include <linux/types.h>

#include <nvhe/spinlock.h>

extern void *kvm_hyp_stacks[];
extern phys_addr_t __phys_hyp_pgd;
extern pgd_t* __hyp_pgd;
extern u64 __io_map_base;
extern nvhe_spinlock_t __hyp_pgd_lock;

void __kvm_init_switch_pgd(phys_addr_t phys, unsigned long size,
			   phys_addr_t pgd, void *sp, void *cont_fn);

int hyp_mm_early_pgtables(phys_addr_t phys, void* virt, unsigned long size,
			  phys_addr_t bp_vect_pa, unsigned long nr_cpus,
			  phys_addr_t *per_cpu_base);

unsigned long hyp_early_alloc_nr_pages(void);


#endif /* __KVM_HYP_SETUP_H */
