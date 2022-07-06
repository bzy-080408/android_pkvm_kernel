#include <nvhe/trace.h>

#include <asm/kvm_hypevents.h>

int __pkvm_start_tracing(unsigned long kern_va, unsigned int first_buf_order)
{
	struct hyp_trace_rb_args *args;
	int err;

	err = __hyp_trace_rb_read_args(kern_va, first_buf_order, &args);
	if (err)
		return err;

	return __hyp_trace_rb_start(args);
}

void __pkvm_stop_tracing(void)
{
	__hyp_trace_rb_stop();
}
