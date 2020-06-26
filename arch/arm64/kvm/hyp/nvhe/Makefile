# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module, HYP/nVHE part
#

asflags-y := -D__KVM_NVHE_HYPERVISOR__
ccflags-y := -D__KVM_NVHE_HYPERVISOR__ -fno-stack-protector \
	     -DDISABLE_BRANCH_PROFILING $(DISABLE_STACKLEAK_PLUGIN) \
	     -I$(srctree)/$(src)/../include

lib-objs := clear_page.o copy_page.o memcpy.o memset.o
lib-objs := $(addprefix ../../../lib/, $(lib-objs))

obj-y := el2.o

hyp-y := ../vgic-v3-sr.o ../timer-sr.o timer-sr.o ../aarch32.o \
	 ../vgic-v2-cpuif-proxy.o sysreg-sr.o debug-sr.o ../entry.o switch.o \
	 ../fpsimd.o tlb.o hyp-init.o hyp-start.o hyp-main.o ../hyp-entry.o \
	$(lib-objs) early_alloc.o  page_alloc.o mm_init.o mmu.o setup.o
hyp-y += stubs.o

obj-$(CONFIG_DEBUG_PREEMPT) += percpu.o

hyp-y := $(patsubst %.o,%.hyp.o,$(hyp-y))
extra-y := $(patsubst %.hyp.o,%.hyp.tmp.o,$(hyp-y)) el2.o

$(obj)/%.hyp.tmp.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/%.hyp.tmp.o: $(src)/%.S FORCE
	$(call if_changed_rule,as_o_S)
$(obj)/%.hyp.o: $(obj)/%.hyp.tmp.o FORCE
	$(call if_changed,hypcopy)

$(obj)/el2.o: $(addprefix $(obj)/,$(hyp-y)) FORCE
	$(call if_changed,ld)

quiet_cmd_hypcopy = HYPCOPY $@
      cmd_hypcopy = $(OBJCOPY)	--prefix-symbols=__kvm_nvhe_		\
				--rename-section=.text=.hyp.text	\
				--rename-section=.bss=.hyp.bss			\
				--rename-section=.data..percpu=.hyp.data..percpu \
				--rename-section=.data..percpu..read_mostly=.hyp.data..percpu..read_mostly \
				$< $@

# Remove ftrace and Shadow Call Stack CFLAGS.
# This is equivalent to the 'notrace' and '__noscs' annotations.
KBUILD_CFLAGS := $(filter-out $(CC_FLAGS_FTRACE) $(CC_FLAGS_SCS), $(KBUILD_CFLAGS))

# KVM nVHE code is run at a different exception code with a different map, so
# compiler instrumentation that inserts callbacks or checks into the code may
# cause crashes. Just disable it.
GCOV_PROFILE	:= n
KASAN_SANITIZE	:= n
UBSAN_SANITIZE	:= n
KCOV_INSTRUMENT	:= n

# Skip objtool checking for this directory because nVHE code is compiled with
# non-standard build rules.
OBJECT_FILES_NON_STANDARD := y
