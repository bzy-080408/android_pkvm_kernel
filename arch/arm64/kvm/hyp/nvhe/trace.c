#include <nvhe/mem_protect.h>
#include <nvhe/mm.h>
#include <nvhe/pkvm.h>
#include <nvhe/trace.h>

DEFINE_PER_CPU(struct hyp_shared_buf, trace_rb);

static int hyp_shared_buf_init(struct hyp_shared_buf *buf, unsigned long kern_va,
			       unsigned int order)
{
	enum kvm_pgtable_prot prot = pkvm_mkstate(PAGE_HYP, PKVM_PAGE_SHARED_OWNED);
	unsigned long size = PAGE_SIZE << order;
	void *start = (void *)kern_hyp_va(kern_va);
	int ret;

	ret = pkvm_create_mappings(start, start + size, prot);
	if (ret)
		return ret;

	ret = host_stage2_wrprotect((u64)start, size);
	if (ret)
		goto err_unmap;

	buf->va = (unsigned long)start;
	buf->order = order;

	return 0;

err_unmap:
	pkvm_remove_mappings(start, start + size);

	return ret;
}

static void hyp_shared_buf_ready(struct hyp_shared_buf *buf)
{
	atomic_set(&buf->lock, SHARED_BUF_READY);
}

static void hyp_shared_buf_free(struct hyp_shared_buf *buf)
{
	unsigned long size = PAGE_SIZE << buf->order;
	void *start = (void *)buf->va;

	/* Wait for the buffer to be released by a writer */
	while (atomic_cmpxchg_relaxed(&buf->lock, SHARED_BUF_READY, SHARED_BUF_UNUSED)
		== SHARED_BUF_WRITE)
	;

	return pkvm_remove_mappings(start, start + size);
}

static void hyp_trace_rb_init(struct hyp_trace_rb *rb, struct hyp_shared_buf *buf)
{
	atomic_set(&rb->hdr.write_idx, 0);
	rb->hdr.order = buf->order;
	hyp_shared_buf_ready(buf);
}

void __hyp_trace_rb_stop(void)
{
	int cpu;

	for (cpu = 0; cpu < hyp_nr_cpus; cpu++) {
		struct hyp_shared_buf *buf = per_cpu_ptr(&trace_rb, cpu);

		if (atomic_read(&buf->lock) == SHARED_BUF_UNUSED)
			continue;

		hyp_shared_buf_free(buf);
	}
}

int __hyp_trace_rb_read_args(unsigned long kern_va, unsigned int first_buf_order,
			     struct hyp_trace_rb_args **args)
{
	struct hyp_shared_buf *buf = per_cpu_ptr(&trace_rb, 0);
	int err;

	err = hyp_shared_buf_init(buf, kern_va, first_buf_order);
	if (err)
		return err;

	*args = (struct hyp_trace_rb_args *)buf->va;

	return 0;
}

int __hyp_trace_rb_start(struct hyp_trace_rb_args *args)
{
	struct hyp_shared_buf *buf = per_cpu_ptr(&trace_rb, 0);
	struct hyp_trace_rb *rb;
	int cpu, ret;

	/* The first buffer is mapped, we can unfold the others */
	for (cpu = 1; cpu < hyp_nr_cpus; cpu++) {
		buf = per_cpu_ptr(&trace_rb, cpu);

		ret = hyp_shared_buf_init(buf, args->kern_va[cpu], args->order[cpu]);
		if (ret)
			break;

		rb = (void *)buf->va;
		hyp_trace_rb_init(rb, buf);
	}

	if (ret) {
		__pkvm_stop_tracing();
		return ret;
	}

	/* args are read... we can now repurpose the buffer */
	buf = per_cpu_ptr(&trace_rb, 0);
	rb = (void *)buf->va;
	hyp_trace_rb_init(rb, buf);

	return 0;
}
