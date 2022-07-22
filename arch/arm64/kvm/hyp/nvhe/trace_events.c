#include <linux/build_bug.h>

#include <nvhe/trace.h>

#undef HYP_EVENT
#define HYP_EVENT(__name, __id, __proto, __struct, __assign) \
	atomic_t __name##_enabled = ATOMIC_INIT(0)
#include <asm/kvm_hypevents.h>

#undef __ARM64_KVM_HYPEVENTS_H_
#undef HYP_EVENT
#define HYP_EVENT(__name, __id, __proto, __struct, __assign)	\
do {								\
	if (events & (1 << __id))				\
		atomic_set(&__name##_enabled, 1);		\
	else							\
		atomic_set(&__name##_enabled, 0);		\
} while (0)

static void enable_hyp_events(u64 events)
{
#include <asm/kvm_hypevents.h>
}

int __pkvm_start_tracing(unsigned long kern_va, unsigned int first_buf_order)
{
	struct hyp_trace_rb_args *args;
	int err;

	BUILD_BUG_ON(sizeof(args->events) < __NUM_HYP_EVENTS);

	err = __hyp_trace_rb_read_args(kern_va, first_buf_order, &args);
	if (err)
		return err;

	enable_hyp_events(args->events);

	return __hyp_trace_rb_start(args);
}

void __pkvm_stop_tracing(void)
{
	enable_hyp_events(0);

	__hyp_trace_rb_stop();
}
