// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Fuad Tabba <tabba@google.com>
 */

/*
 * Basic tests for protected VMs.
 *
 * These tests require Protected KVM to run. Protected KVM is enabled via the
 * kvm-arm.mode=protected kernel parameter.
 */

#include "arm-smccc.h"
#include "kvm_util.h"
#include "test_util.h"
#include "processor.h"
#include "sysreg.h"

u64 hvc(u64 arg0, u64 arg1, u64 arg2, u64 arg3)
{
	register u64 r0 __asm__("x0") = arg0;
	register u64 r1 __asm__("x1") = arg1;
	register u64 r2 __asm__("x2") = arg2;
	register u64 r3 __asm__("x3") = arg3;

	__asm__ volatile(
		"hvc #0"
		: /* Output registers, also used as inputs ('+' constraint). */
		"+r"(r0), "+r"(r1), "+r"(r2), "+r"(r3)
		:
		: /* Clobber registers. */
		"x4", "x5", "x6", "x7");

	return r0;
}

/*
 * Additional ucalls for printing guest values.
 */

/* Print a constant string. */
#define UCALL_PR_STR (UCALL_LAST + 1)
#define PR_STR(value) ucall(UCALL_PR_STR, 1, value)
static void pr_str(struct ucall *uc)
{
	const char *str = (const char *)uc->args[0];

	pr_info("%s", str);
}

/* Print a uint64_t. */
#define UCALL_PR_U64 (UCALL_LAST + 2)
#define PR_U64(value) ucall(UCALL_PR_U64, 1, value)
static void pr_u64(struct ucall *uc)
{
	uint64_t value = (uint64_t)uc->args[0];

	pr_info("guest value: 0x%016lx\n", value);
}
/* Print a constant string and a uint64_t. */
#define UCALL_PR_STR_U64 (UCALL_LAST + 3)
#define PR_STR_U64(str, value) ucall(UCALL_PR_STR_U64, 2, str, value)
static void pr_str_u64(struct ucall *uc)
{
	const char *str = (const char *)uc->args[0];
	uint64_t value = (uint64_t)uc->args[1];

	pr_info("%s=0x%016lx\n", str, value);
}

/* Print a system register and its value.*/
#define print_sysreg(name) PR_STR_U64(#name, read_sysreg_s(SYS_ ## name))

//uint32_t vcpu_ids[] = {0, 1, 2, 3, 4, 5, 6, 7};
uint32_t vcpu_ids[] = {0};
#define NUM_VCPUS  ARRAY_SIZE(vcpu_ids)
#define NUM_VMS	1

/* For tracking the run state of a protected VM. */
struct test_vm {
	struct kvm_vm *vm;
	bool vcpus_done[NUM_VCPUS];
	int num_done;
	unsigned int run_next;
};

/*
 * Beginning of guest code
 */

/* Counter for the number of exceptions (cur_spx_sync) taken by the guest. */
static volatile uint64_t num_exceptions;

/*
 * Exception handler callback called via synchronous exceptions (cur_spx_sync).
 *
 * Increment num_exceptions for every exception taken.
 */
static void guest_exception_handler(struct ex_regs *regs)
{
	++num_exceptions;
	regs->pc += 4;
}

/* Assert that the executed code causes n exceptions in the guest. */
#define ASSERT_EXCEPTION_COUNT(code, n)                                        \
	do {                                                                   \
		uint64_t last_num = num_exceptions;                            \
		code;                                                          \
		GUEST_ASSERT(num_exceptions == last_num + (n));                \
	} while (0)

/* Assert that the executed code causes one exception in the guest. */
#define ASSERT_EXCEPTION(code) ASSERT_EXCEPTION_COUNT(code, 1)

/* Assert that the executed code does not cause any exceptions in the guest. */
#define ASSERT_NO_EXCEPTION(code) ASSERT_EXCEPTION_COUNT(code, 0)

/* Assert that reading the register causes an exception. */
#define ASSERT_EXCEPTION_READ(reg) \
	ASSERT_EXCEPTION(read_sysreg_s(reg))

/* Assert that writing to the register causes an exception. */
#define ASSERT_EXCEPTION_WRITE(reg) \
	ASSERT_EXCEPTION(write_sysreg_s(0, reg))

/* Assert that reading from and writing to the register causes exceptions. */
#define ASSERT_EXCEPTION_READ_WRITE(reg)				\
do {									\
	ASSERT_EXCEPTION_READ(reg);					\
	ASSERT_EXCEPTION_WRITE(reg);					\
} while (0)

/* Assert that reading the register doesn't cause an exception. */
#define ASSERT_NO_EXCEPTION_READ(reg) \
	ASSERT_NO_EXCEPTION(read_sysreg_s(reg))

/* Assert that writing to the register doesn't cause an exception. */
#define ASSERT_NO_EXCEPTION_WRITE(reg) \
	ASSERT_NO_EXCEPTION(write_sysreg_s(0, reg))

/* Assert that reading from/writing to the register doesn't cause exceptions. */
#define ASSERT_NO_EXCEPTION_READ_WRITE(reg)				\
do {									\
	ASSERT_NO_EXCEPTION_READ(reg);					\
	ASSERT_NO_EXCEPTION_WRITE(reg);					\
} while (0)


/* Guest start function */
static void guest_code(void)
{
	volatile int *x = (int *) 0x13;
	u64 res;

	PR_STR("Hello world!\n");
	print_sysreg(ID_AA64PFR0_EL1);

	ASSERT_EXCEPTION_READ_WRITE(SYS_RGSR_EL1);

	ASSERT_EXCEPTION(*x);
	print_sysreg(ESR_EL1);
	print_sysreg(FAR_EL1);
	GUEST_ASSERT(read_sysreg_s(SYS_FAR_EL1) == (u64) x);

	res = hvc(ARM_SMCCC_VERSION_FUNC_ID, 0, 0, 0);
	PR_STR_U64("ARM_SMCCC_VERSION_FUNC_ID", res);

	GUEST_ASSERT(res == ARM_SMCCC_VERSION_1_1);

	GUEST_DONE();
}

/* Run the next vcpu still waiting in the VM in a round-robin fashion. */
bool run_vm(struct test_vm *vm, struct ucall *uc)
{
	int i;
	struct kvm_run *run;
	uint32_t vcpu_id;
	uint32_t vcpu_idx;

	if (vm->num_done == NUM_VCPUS)
		return true;

	for (i = 0; i < NUM_VCPUS ; i++) {
		vcpu_idx = (vm->run_next++) % NUM_VCPUS;
		if (!vm->vcpus_done[vcpu_idx])
			break;
	}

	vcpu_id = vcpu_ids[vcpu_idx];
	pr_info("%d\n", vcpu_id);

	vcpu_run(vm->vm, vcpu_id);

	switch (get_ucall(vm->vm, vcpu_id, uc)) {
	case UCALL_DONE:
		vm->vcpus_done[vcpu_idx] = true;
		vm->num_done++;
		break;
	case UCALL_ABORT:
		/* Handles guest failed assertions. */
		TEST_FAIL("%s at %s:%ld",
				(const char *)uc->args[0],
				__FILE__,
				uc->args[1]);
		break;
	case UCALL_PR_STR:
		pr_str(uc);
		break;
	case UCALL_PR_U64:
		pr_u64(uc);
		break;
	case UCALL_PR_STR_U64:
		pr_str_u64(uc);
		break;
	default:
		run = vcpu_state(vm->vm, vcpu_id);
		TEST_FAIL("Unexpected exit: %s",
			exit_reason_str(run->exit_reason));
		break;
	}

	return vm->num_done == NUM_VCPUS;
}

int main(int ac, char **av)
{
	struct test_vm vms[NUM_VMS];
	struct ucall uc;
	int i;
	int max_vms;
	int num_done = 0;
	bool pkvm_enabled = kvm_check_cap(KVM_CAP_ARM_PROTECTED_VM);

	struct kvm_enable_cap cap = {
		.cap = KVM_CAP_ARM_PROTECTED_VM,
		.flags = KVM_CAP_ARM_PROTECTED_VM_FLAGS_ENABLE,
		.args[0] = -1, /* No firmware. */
	};

	if (!pkvm_enabled) {
		fprintf(stderr, "Protected KVM not available.\n");
	} else {
		//max_vms = kvm_check_cap(KVM_CAP_ARM_NR_PROTECTED_VMS);
		//pr_info("The number of supported protected VMs is %d.\n", max_vms);

		//TEST_ASSERT(
		//	max_vms > 0,
		//	"KVM_CAP_ARM_NR_PROTECTED_VMS should be >= 1. Got: %d\n",
		//	max_vms);
	}

	/* Create VMs with multiple vcpus. */
	memset(vms, 0, sizeof(vms));
	for (i = 0; i < NUM_VMS; i++) {
		int vcpu_id = 0;
		vms[i].vm = vm_create_default_with_vcpus(NUM_VCPUS, 0, 0,
							 guest_code, vcpu_ids);

		/* Mark the VM as a protected VM. */
		if (pkvm_enabled)
			vm_enable_cap(vms[i].vm, &cap);

		ucall_init(vms[i].vm, NULL);

		vm_init_descriptor_tables(vms[i].vm);

		for (vcpu_id = 0; vcpu_id < NUM_VCPUS; ++vcpu_id)
			vcpu_init_descriptor_tables(vms[i].vm, vcpu_id);

        	vm_install_sync_handler(vms[i].vm, VECTOR_SYNC_CURRENT,
                        ESR_EC_UNKNOWN, guest_exception_handler);

        	vm_install_sync_handler(vms[i].vm, VECTOR_SYNC_CURRENT,
                        ESR_EC_BRK_INS, guest_exception_handler);

        	vm_install_sync_handler(vms[i].vm, VECTOR_SYNC_CURRENT,
                        ESR_EC_DABT_CURRENT, guest_exception_handler);
	}

	/* Run the VMs. */
	while (num_done != NUM_VMS) {
		num_done = 0;
		for (int i = 0; i < NUM_VMS; i++) {
			pr_info("Running vm:vcpu %d:", i);
			num_done += run_vm(&vms[i], &uc);
		}
	}

	pr_info("Tests passed.\n");
	return 0;
}
