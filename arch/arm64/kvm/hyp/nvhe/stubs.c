char __hyp_panic_string[] = "__hyp_panic_string";
void panic(const char *fmt, ...) {}

unsigned long __hyp_stub_vectors;
unsigned long hyp_va_bits;
unsigned long idmap_t0sz;
unsigned long kimage_voffset;

unsigned long __per_cpu_start;
unsigned long __per_cpu_end;

unsigned long __start_rodata;
unsigned long __end_rodata;
unsigned long __bss_start;
unsigned long __bss_stop;

unsigned long __start___kvm_ex_table;
unsigned long __stop___kvm_ex_table;

unsigned long __hyp_idmap_text_start;
unsigned long __hyp_idmap_text_end;
unsigned long __hyp_text_start;
unsigned long __hyp_text_end;
unsigned long __hyp_bss_start;
unsigned long __hyp_bss_end;

void arm64_enable_wa2_handling(void) {}
void kvm_patch_vector_branch(void) {}
void kvm_update_va_mask(void) {}
void sve_save_state(void) {}
void sve_load_state(void) {}

// /* Data shared with the kernel. */
unsigned long cpu_hwcaps;
unsigned long cpu_hwcap_keys;
unsigned long __icache_flags;
unsigned long kvm_vgic_global_state;
unsigned long __kvm_bp_vect_base;
unsigned long arm64_ftr_reg_ctrel0;

unsigned long arm64_const_caps_ready;
unsigned long gic_pmr_sync;
unsigned long vgic_v2_cpuif_trap;
unsigned long vgic_v3_cpuif_trap;
