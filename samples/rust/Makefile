# SPDX-License-Identifier: GPL-2.0

$(obj)/hyp/kvm_nvhe.o: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/hyp $(obj)/hyp/kvm_nvhe.o

clean-files := hyp/hyp.lds hyp/hyp-reloc.S

obj-$(CONFIG_SAMPLE_RUST_MINIMAL)		+= rust_minimal.o

RUSTFLAGS_rust_minimal_host.o += -A improper-ctypes # For __uint_128_t

rust_minimal-y := rust_minimal_host.o hyp/kvm_nvhe.o

subdir-$(CONFIG_SAMPLE_RUST_HOSTPROGS)		+= hostprogs
