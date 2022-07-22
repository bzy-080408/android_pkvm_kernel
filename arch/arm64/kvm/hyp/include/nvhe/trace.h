#ifndef __ARM64_KVM_HYP_NVHE_TRACE_H
#define __ARM64_KVM_HYP_NVHE_TRACE_H

#include <asm/kvm_hyptrace.h>
#include <asm/kvm_hypevents_defs.h>
#include <asm/percpu.h>
#include <asm/arch_timer.h>

#include <linux/build_bug.h>
#include <linux/types.h>

#define SHARED_BUF_UNUSED 0
#define SHARED_BUF_READY 1
#define SHARED_BUF_WRITE 2

struct hyp_shared_buf {
	unsigned long va;
	unsigned order;
	atomic_t lock;
};

DECLARE_PER_CPU(struct hyp_shared_buf, trace_rb);

static inline bool __start_write_shared_buf(struct hyp_shared_buf *buf)
{
	return atomic_cmpxchg_relaxed(&buf->lock, SHARED_BUF_READY, SHARED_BUF_WRITE)
		!= SHARED_BUF_UNUSED;
}

static inline void __stop_write_shared_buf(struct hyp_shared_buf *buf)
{
	atomic_set(&buf->lock, SHARED_BUF_READY);
}

static inline struct hyp_trace_evt *__trace_rb_next(struct hyp_trace_rb *rb)
{
	return rb->events + __hyp_trace_rb_next_idx(rb);
}

int __hyp_trace_rb_read_args(unsigned long kern_va, unsigned int first_buf_order,
			     struct hyp_trace_rb_args **args);
int __hyp_trace_rb_start(struct hyp_trace_rb_args *args);
void __hyp_trace_rb_stop(void);

int __pkvm_start_tracing(unsigned long kern_va, unsigned int first_buf_order);
void __pkvm_stop_tracing(void);

#define HYP_EVENT(__name, __id, __proto, __struct, __assign)			\
	HYP_EVENT_FORMAT(__name, __struct)					\
	extern atomic_t __name##_enabled;					\
	static inline void trace_hyp_##__name(__proto)				\
	{									\
		struct hyp_shared_buf *buf = this_cpu_ptr(&trace_rb);		\
		struct hyp_trace_rb *rb = (struct hyp_trace_rb *)buf->va;	\
		struct hyp_trace_evt *__entry_raw;				\
		struct trace_hyp_format_##__name *__entry;			\
										\
		BUILD_BUG_ON(sizeof(struct trace_hyp_format_##__name) >		\
			     sizeof(struct hyp_trace_evt_args));		\
										\
		if (!atomic_read(&__name##_enabled))				\
			return;							\
		if (!__start_write_shared_buf(buf))				\
			return;							\
		__entry_raw = __trace_rb_next(rb);				\
		__entry_raw->id = __id;						\
		__entry_raw->timestamp = __arch_counter_get_cntpct();		\
		__entry = (struct trace_hyp_format_##__name *)&__entry_raw->args;\
		__assign							\
		atomic_inc(&rb->hdr.write_idx);					\
		__stop_write_shared_buf(buf);					\
	}

#endif
