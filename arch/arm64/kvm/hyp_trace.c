#include <linux/arm-smccc.h>
#include <linux/debugfs.h>
#include <linux/mutex.h>
#include <linux/percpu-defs.h>

#include <linux/sched/clock.h>
#include <linux/memblock.h>

#include <asm/kvm_host.h>
#include <asm/kvm_hyptrace.h>
#include <asm/kvm_hypevents.h>

struct trace_buf {
	unsigned long va;
	int order;
	int flags;
};

#define TRACE_BUF_MEMBLOCK (1 << 0)
#define TRACE_BUF_RB_INIT (1 << 1)		/* hyp_trace_rb init by hyp */

static DEFINE_MUTEX(mutex);
static DEFINE_PER_CPU(struct trace_buf, trace_buf) = { .va = 0, .flags = 0 };
static u64 events_on;
static bool hyp_tracing_is_on;

static unsigned long __trace_buf_prealloc[8] = {0};

/*
 * TODO: to be replaced by dynamic allocation after hyptrace is plugged to
 * host trace_events.
 */
void __init hyp_trace_buf_preallocate(void)
{
	int cpu;

	/*
	 * Ahem ... this is init _before_ the CPUs are online and
	 * the cpu_possible_mask is therefore empty here...
	 *
	 * ...But it's just for quick debug right? So let's just allocate what
	 * we need for 8 CPUs and move on.
	 */
	for (cpu = 0; cpu < 8; cpu++) {
		phys_addr_t base =
			memblock_phys_alloc(PAGE_SIZE << 13, PAGE_SIZE);

		if (!base) {
			pr_warn("Failed to pre-allocate hyp_trace for cpu %d\n", cpu);
			continue;
		}

		__trace_buf_prealloc[cpu] = (unsigned long)phys_to_virt(base);

		pr_info("Reserved %lu MiB at 0x%lx for hyp_trace CPU %d\n",
			PAGE_SIZE >> 7, __trace_buf_prealloc[cpu], cpu);
	}
}

static int hyp_trace_buf_use_preallocation(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct trace_buf *buf = per_cpu_ptr(&trace_buf, cpu);

		if (cpu >= 8)
			break;

		buf->va = __trace_buf_prealloc[cpu];
		buf->order = 13;
		buf->flags |= TRACE_BUF_MEMBLOCK;
	}

	return 0;
}
late_initcall(hyp_trace_buf_use_preallocation);

static void hyp_trace_free_buf(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct trace_buf *buf = per_cpu_ptr(&trace_buf, cpu);

		if (!buf->va || buf->flags & TRACE_BUF_MEMBLOCK)
			continue;

		free_page(buf->va);
		buf->va = 0;
		buf->order = 0;
	}
}

static int hyp_trace_start(void)
{
	struct hyp_trace_rb_args *args;
	struct trace_buf *buf;
	unsigned int order;
	int cpu, ret = 0;

	mutex_lock(&mutex);

	if (hyp_tracing_is_on)
		goto end;

	/* First buffer used to store the address of all others */
	buf = per_cpu_ptr(&trace_buf, 0);

	if (!buf->va) {
		args = (struct hyp_trace_rb_args *)__get_free_page(GFP_KERNEL);
		buf->va = (unsigned long)args;
		buf->order = 0;
		order = 0;
	} else {
		args = (struct hyp_trace_rb_args *)buf->va;
		order = buf->order;
	}

	if (!args) {
		ret = -ENOMEM;
		goto end;
	}

	/* The first buffer embedding the arguments is too small */
	if (sizeof(*args) > PAGE_SIZE << order) {
		ret = -EINVAL;
		goto end;
	}

	for_each_possible_cpu(cpu) {
		buf = per_cpu_ptr(&trace_buf, cpu);

		if (!buf->va) {
			buf->va = (unsigned long)__get_free_page(GFP_KERNEL);
			buf->order = 0;
		}

		if (!buf->va) {
			ret = -ENOMEM;
			goto end;
		}

		args->kern_va[cpu] = buf->va;
		args->order[cpu] = buf->order;
	}

	args->events = events_on;

	ret = kvm_call_hyp_nvhe(__pkvm_start_tracing, args, order);

	if (!ret) {
		hyp_tracing_is_on = true;
		for_each_possible_cpu(cpu) {
			buf = per_cpu_ptr(&trace_buf, cpu);
			if (buf->va)
				buf->flags |= TRACE_BUF_RB_INIT;
		}
	}

end:
	if (ret)
		hyp_trace_free_buf();

	mutex_unlock(&mutex);

	return ret;
}

static void hyp_trace_stop(void)
{
	mutex_lock(&mutex);

	if (!hyp_tracing_is_on)
		goto end;

	kvm_call_hyp_nvhe(__pkvm_stop_tracing);

	hyp_tracing_is_on = false;
end:
	mutex_unlock(&mutex);
}

static ssize_t
hyp_tracing_on(struct file *filp, const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	char c;
	int err;

	if (cnt != 2)
		return -EINVAL;

	if (get_user(c, ubuf))
		return -EFAULT;

	switch (c) {
	case '1':
		err = hyp_trace_start();
		if (err)
			return err;
		break;
	case '0':
		hyp_trace_stop();
		break;
	default:
			return -EINVAL;
	}

	return cnt;
}

static const struct file_operations hyp_tracing_on_fops = {
	.write  = hyp_tracing_on,
};

struct trace_buf_iterator {
	unsigned long read_idx[NR_CPUS];
	int *pfn_to_cpu;
	int min_pfn;
	int max_pfn;
};

static void trace_buf_iterator_init(struct trace_buf_iterator *it)
{
	int i, cpu, min_pfn = INT_MAX, max_pfn = INT_MIN, num_pfn = 0;

	for_each_possible_cpu(cpu) {
		struct trace_buf *buf = per_cpu_ptr(&trace_buf, cpu);
		int pfn_start, pfn_end;

		if (!buf->va)
			continue;

		pfn_start = virt_to_pfn(buf->va);
		pfn_end = pfn_start + (1 << buf->order) - 1;

		min_pfn = min(min_pfn, pfn_start);
		max_pfn = max(max_pfn, pfn_end);
	}

	/* No trace_buf has been init. */
	if (max_pfn == INT_MIN)
		return;

	it->min_pfn = min_pfn;
	it->max_pfn = max_pfn;

	num_pfn = it->max_pfn - it->min_pfn + 1;

	it->pfn_to_cpu = kmalloc_array(num_pfn, sizeof(int), GFP_KERNEL);
	for (i = 0; i < num_pfn; i++)
		it->pfn_to_cpu[i] = -1;

	for_each_possible_cpu(cpu) {
		struct trace_buf *buf = per_cpu_ptr(&trace_buf, cpu);
		int pfn = virt_to_pfn(buf->va);
		int pfn_end = pfn + (1 << buf->order) - 1;

		for (; pfn <= pfn_end; pfn++)
			it->pfn_to_cpu[pfn - min_pfn] = cpu;
	}
}

static void trace_buf_iterator_clear(struct trace_buf_iterator *it)
{
	kfree(it->pfn_to_cpu);
}

static int trace_buf_va_to_cpu(struct trace_buf_iterator *it, void *buf_va)
{
	int pfn = virt_to_pfn(buf_va);

	if (pfn > it->max_pfn || pfn < it->min_pfn)
		return -1;

	return it->pfn_to_cpu[pfn - it->min_pfn];
}

static void *__ht_next(struct seq_file *m, loff_t *pos)

{
	struct trace_buf_iterator *it = m->private;
	struct hyp_trace_evt *next_evt = NULL;
	int cpu, next_evt_cpu;

	for_each_possible_cpu(cpu) {
		struct trace_buf *buf = per_cpu_ptr(&trace_buf, cpu);
		struct hyp_trace_rb *rb = (struct hyp_trace_rb *)buf->va;
		struct hyp_trace_evt *evt;
		int write_idx;

		if (!rb || !(buf->flags & TRACE_BUF_RB_INIT))
			continue;

		write_idx = __hyp_trace_rb_next_idx(rb);
		evt = rb->events + it->read_idx[cpu];

		if (it->read_idx[cpu] >= write_idx)
			continue;

		if (next_evt && evt->timestamp >= next_evt->timestamp)
			continue;

		next_evt = evt;
		next_evt_cpu = cpu;
	}

	if (next_evt)
		it->read_idx[next_evt_cpu]++;

	return next_evt;
}

static void *ht_start(struct seq_file *m, loff_t *pos)
{
	if (*pos == 0)
		return SEQ_START_TOKEN;

	return __ht_next(m, pos);
}

static void *ht_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;

	return ht_start(m, pos);
}

static void ht_stop(struct seq_file *m, void *v) { }

static void ht_print_cpu(struct seq_file *m, struct hyp_trace_evt *evt_raw)
{
	struct trace_buf_iterator *it = m->private;
	int cpu = trace_buf_va_to_cpu(it, evt_raw);

	seq_printf(m, "[%03d] ", cpu);
}

static void ht_print_time(struct seq_file *m, struct hyp_trace_evt *evt_raw)
{
	unsigned long long t = __cnt_to_sched_clock(evt_raw->timestamp);
	unsigned long secs, usecs_rem;

	do_div(t, 1000);
	usecs_rem = do_div(t, USEC_PER_SEC);
	secs = (unsigned long)t;

	seq_printf(m, "[%5lu.%06lu] ", secs, usecs_rem);
}

static int ht_show(struct seq_file *m, void *v)
{
	struct hyp_trace_evt *evt_raw = v;

	if (v == SEQ_START_TOKEN) {
		int cpu;

		seq_printf(m, "Tracing is %s\n", hyp_tracing_is_on ? "ON" : "OFF");

		for_each_possible_cpu(cpu) {
			struct trace_buf *buf = per_cpu_ptr(&trace_buf, cpu);
			struct hyp_trace_rb *rb = (struct hyp_trace_rb *)buf->va;

			if (!rb || !(buf->flags & TRACE_BUF_RB_INIT))
				continue;

			seq_printf(m, "CPU%d: write_idx=%d num_events=%d max_events=%llu",
					cpu,
					atomic_read(&rb->hdr.write_idx),
					__hyp_trace_rb_next_idx(rb),
					__hyp_trace_rb_max_entries(rb));

			if (atomic_read(&rb->hdr.write_idx) > __hyp_trace_rb_max_entries(rb))
				seq_puts(m, " WARNING: EVENTS LOST");

			seq_puts(m, "\n");
		}

		return 0;
	}

	ht_print_time(m, evt_raw);
	ht_print_cpu(m, evt_raw);

	switch (evt_raw->id) {
		case HYP_EVT_ENTER: {
			struct trace_hyp_format_hyp_enter *evt =
				(struct trace_hyp_format_hyp_enter *)&evt_raw->args;
			seq_printf(m, "hyp_enter: esr=0x%016llx x0=0x%016llx vmid=%u\n",
				evt->esr, evt->x0, evt->vmid);
			break;
		} case HYP_EVT_EXIT: {
			seq_puts(m, "hyp_exit\n");
			break;
		} case HYP_EVT_POP_MEMCACHE: {
			struct trace_hyp_format_pop_hyp_memcache *evt =
				(struct trace_hyp_format_pop_hyp_memcache *)&evt_raw->args;
			seq_printf(m, "pop_hyp_memcache: mc=0x%llx paddr=0x%llx nr_pages=%u\n",
				evt->mc, evt->paddr, evt->nr_pages);
			break;
		} case HYP_EVT_PUSH_MEMCACHE: {
			struct trace_hyp_format_push_hyp_memcache *evt =
				(struct trace_hyp_format_push_hyp_memcache *)&evt_raw->args;
			seq_printf(m, "push_hyp_memcache: mc=0x%llx paddr=0x%llx nr_pages=%u\n",
				evt->mc, evt->paddr, evt->nr_pages);
			break;
		} case HYP_EVT_COALESCED_BLOCK: {
			struct trace_hyp_format_hyp_coalesced *evt =
				(struct trace_hyp_format_hyp_coalesced *)&evt_raw->args;
			seq_printf(m, "hyp_coalesced: start=0x%016llx end=0x%016llx level=%u\n",
				   evt->addr, evt->end, evt->level);
			break;
		} default:
			seq_printf(m, "UNKNOWN HYP EVENT ID:%d\n", evt_raw->id);
	}

	return 0;
}

static const struct seq_operations hyp_trace_ops = {
	.start = ht_start,
	.next  = ht_next,
	.stop  = ht_stop,
	.show  = ht_show,
};

static int hyp_trace_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &hyp_trace_ops);
	struct seq_file *m = file->private_data;
	struct trace_buf_iterator *it;

	if (ret)
		return ret;

	mutex_lock(&mutex);

	it = kzalloc(sizeof(*it), GFP_KERNEL);
	trace_buf_iterator_init(it);

	m->private = it;

	return 0;

}

int hyp_trace_release(struct inode *inode, struct file *file)
{
	struct trace_buf_iterator *it = ((struct seq_file *)file->private_data)->private;

	trace_buf_iterator_clear(it);
	kfree(it);

	mutex_unlock(&mutex);

	return seq_release(inode, file);
}

static const struct file_operations hyp_trace_fops = {
	.open  = hyp_trace_open,
	.read  = seq_read,
	.llseek = seq_lseek,
	.release = hyp_trace_release,
};

static void hyp_create_trace_debugfs(struct dentry *parent)
{
	if (!debugfs_create_file("trace", 0600, parent,
				 NULL, &hyp_trace_fops))
		pr_warn("Failed create hyp-tracing/trace\n");
}

static ssize_t
hyp_events_write(struct file *filp, const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	char c;
	unsigned long event_id = (unsigned long)((struct seq_file *)filp->private_data)->private;

	if (cnt != 2)
		return -EINVAL;

	if (get_user(c, ubuf))
		return -EFAULT;

	switch (c) {
	case '1':
		events_on |= (1 << event_id);
		break;
	case '0':
		events_on &= ~(1 << event_id);
		break;
	default:
			return -EINVAL;
	}

	return cnt;
}

static int hyp_events_show(struct seq_file *m, void *v)
{
	unsigned long event_id = (unsigned long)m->private;

	seq_printf(m, "%d\n", (events_on & (1 << event_id)) ? 1 : 0);

	return 0;
}

static int hyp_events_open(struct inode *inode, struct file *filp)
{
	return single_open(filp, hyp_events_show, inode->i_private);
}

static const struct file_operations hyp_events_fops = {
	.open		= hyp_events_open,
	.write		= hyp_events_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void hyp_create_events_debugfs(struct dentry *parent)
{
	struct dentry *d = debugfs_create_dir("events", parent);

	if (!d) {
		pr_err("Failed to create debugfs dir events\n");
		return;
	}

#undef __ARM64_KVM_HYPEVENTS_H_
#undef HYP_EVENT
#define HYP_EVENT(__name, __id, __proto, __struct, __assign) \
	debugfs_create_file(#__name, 0700, d, (void *)__id, &hyp_events_fops)

#include <asm/kvm_hypevents.h>
}

static int __init hyp_tracing_debugfs(void)
{
	struct dentry *debugfs_folder, *d;

	debugfs_folder = debugfs_create_dir("hyp-tracing", NULL);

	if (!debugfs_folder) {
		pr_err("Failed to create debugfs folder hyp-tracing\n");
		return -ENODEV;
	}

	d = debugfs_create_file("tracing_on", 0700, debugfs_folder, NULL, &hyp_tracing_on_fops);
	if (!d) {
		pr_err("Failed to create file hyp-trace/tracing_on\n");
		return -ENODEV;
	}

	hyp_create_events_debugfs(debugfs_folder);
	hyp_create_trace_debugfs(debugfs_folder);

	return 0;
}
late_initcall(hyp_tracing_debugfs);

