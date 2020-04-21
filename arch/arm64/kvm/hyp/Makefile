# SPDX-License-Identifier: GPL-2.0
#
# Makefile for Kernel-based Virtual Machine module, HYP part
#

ccflags-y += -fno-stack-protector -DDISABLE_BRANCH_PROFILING \
		$(DISABLE_STACKLEAK_PLUGIN)

obj-$(CONFIG_KVM) += vhe/ nvhe/
obj-$(CONFIG_KVM_INDIRECT_VECTORS) += smccc_wa.o
