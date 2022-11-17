obj-m += pkvm-s2mpu_mod.o

$(obj)/hyp/kvm_nvhe.o: FORCE
	$(Q)$(MAKE) $(build)=$(obj)/hyp $(obj)/hyp/kvm_nvhe.o

clean-files := hyp/hyp.lds hyp/hyp-reloc.S

pkvm-s2mpu_mod-y := pkvm-s2mpu.o hyp/kvm_nvhe.o
