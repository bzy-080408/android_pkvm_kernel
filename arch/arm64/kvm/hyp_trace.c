#include <linux/arm-smccc.h>
#include <linux/list.h>
#include <linux/percpu-defs.h>
#include <linux/ring_buffer.h>
#include <linux/workqueue.h>

#include <asm/kvm_host.h>
#include <asm/kvm_hyptrace.h>

#include <linux/sched/clock.h>

#include "hyp_trace.h"

#define RB_POLL_MS 1000

static bool hyp_trace_on;
static int hyp_trace_readers;
static struct trace_buffer *hyp_trace_buffer;
static struct hyp_buffer_pages_backing hyp_buffer_pages_backing;
static DEFINE_MUTEX(hyp_trace_lock);

static int bpage_backing_setup(struct hyp_trace_pack *pack)
{
	size_t backing_size;
	void *start;

	if (hyp_buffer_pages_backing.start)
		return -EBUSY;

	backing_size = sizeof(struct hyp_buffer_page) *
		       pack->trace_buffer_pack.total_pages;
	backing_size = PAGE_ALIGN(backing_size);
	start = alloc_pages_exact(backing_size, GFP_KERNEL_ACCOUNT);
	if (!start)
		return -ENOMEM;

	hyp_buffer_pages_backing.start = (unsigned long)start;
	hyp_buffer_pages_backing.size = backing_size;
	pack->backing.start = (unsigned long)start;
	pack->backing.size = backing_size;

	return 0;
}

static void bpage_backing_teardown(void)
{
	unsigned long backing = hyp_buffer_pages_backing.start;
	unsigned long end = backing + hyp_buffer_pages_backing.size;

	if (!hyp_buffer_pages_backing.start)
		return;

	/* TODO check for power of two */

	for (; backing < end; backing += PAGE_SIZE)
		free_pages(backing, 0);

	hyp_buffer_pages_backing.start = 0;
	hyp_buffer_pages_backing.size = 0;
}

static int __swap_reader_page(int cpu)
{
	return kvm_call_hyp_nvhe(__pkvm_rb_swap_reader_page, cpu);
}

static int __update_footers(int cpu)
{
	return kvm_call_hyp_nvhe(__pkvm_rb_update_footers, cpu);
}

struct ring_buffer_ext_cb hyp_cb = {
	.update_footers = __update_footers,
	.swap_reader = __swap_reader_page,
};

static struct hyp_trace_pack *hyp_trace_pack(struct trace_buffer *trace_buffer,
					     size_t *size)
{
	struct hyp_trace_pack *pack;
	struct clock_read_data *rd;
	unsigned int seq;

	*size = offsetof(struct hyp_trace_pack, trace_buffer_pack) +
		trace_buffer_pack_size(trace_buffer);

	pack = kzalloc(*size, GFP_KERNEL);
	if (!pack)
		return NULL;

	trace_buffer_pack(trace_buffer, &pack->trace_buffer_pack);

	do {
		rd = sched_clock_read_begin(&seq);
		pack->epoch_cyc = rd->epoch_cyc;
		pack->epoch_ns = rd->epoch_ns;
	} while (sched_clock_read_retry(seq));

	return pack;
}

static void hyp_free_tracing(void)
{
	if (!hyp_trace_buffer)
		return;

	ring_buffer_free(hyp_trace_buffer);
	hyp_trace_buffer = NULL;
	bpage_backing_teardown();
}

static int hyp_start_tracing(void)
{
	struct hyp_trace_pack *pack;
	size_t size;
	int ret = 0;

	if (hyp_trace_on || hyp_trace_readers)
		return -EBUSY;

	hyp_free_tracing();

	hyp_trace_buffer = ring_buffer_alloc_ext(PAGE_SIZE * 3, &hyp_cb);
	if (!hyp_trace_buffer)
		return -ENOMEM;

	pack = hyp_trace_pack(hyp_trace_buffer, &size);
	if (!pack) {
		goto err;
		ret = -ENOMEM;
	}

	ret = bpage_backing_setup(pack);
	if (ret)
		goto unpack;

	ret = kvm_call_hyp_nvhe(__pkvm_start_tracing, (unsigned long)pack, size);
unpack:
	kfree(pack);

	if (!ret) {
		hyp_trace_on = true;
		return 0;
	}
err:
	ring_buffer_free(hyp_trace_buffer);
	hyp_trace_buffer = NULL;
	bpage_backing_teardown();

	return ret;
}

static void hyp_stop_tracing(void)
{
	int ret;

	if (!hyp_trace_buffer || !hyp_trace_on)
		return;

	ret = kvm_call_hyp_nvhe(__pkvm_stop_tracing);
	if (ret) {
		WARN_ON(1);
		return;
	}

	hyp_trace_on = false;
}

static ssize_t
hyp_tracing_on(struct file *filp, const char __user *ubuf, size_t cnt, loff_t *ppos)
{
	int err = 0;
	char c;

	if (cnt != 2)
		return -EINVAL;

	if (get_user(c, ubuf))
		return -EFAULT;

	mutex_lock(&hyp_trace_lock);

	switch (c) {
	case '1':
		err = hyp_start_tracing();
		break;
	case '0':
		hyp_stop_tracing();
		break;
	default:
		err = -EINVAL;
	}

	mutex_unlock(&hyp_trace_lock);

	return err ? err : cnt;
}

static const struct file_operations hyp_tracing_on_fops = {
	.write  = hyp_tracing_on,
};

struct ht_iterator {
	struct ring_buffer_iter *buf_iter;
	struct trace_buffer *trace_buffer;
	struct hyp_entry_hdr *ent;
	struct trace_seq seq;
	u64 ts;
	size_t ent_size;
	struct delayed_work poke_work;
	unsigned long lost_events;
	int cpu;
};

static void ht_print_trace_time(struct ht_iterator *iter)
{
	unsigned long usecs_rem;
	u64 ts_ns = iter->ts;

	do_div(ts_ns, 1000);
	usecs_rem = do_div(ts_ns, USEC_PER_SEC);

	trace_seq_printf(&iter->seq, "[%5lu.%06lu] ",
			 (unsigned long)ts_ns, usecs_rem);
}

static void ht_print_trace_fmt(struct ht_iterator *iter)
{
	struct trace_event *e;

	if (iter->lost_events)
		trace_seq_printf(&iter->seq, "CPU:%d [LOST %lu EVENTS]\n",
				 iter->cpu, iter->lost_events);

	/* TODO: format bin/hex/raw */

	ht_print_trace_time(iter);

	trace_seq_printf(&iter->seq, "id=%u ", iter->ent->id);
	trace_seq_printf(&iter->seq, "Unknown event id %d\n", iter->ent->id);
};

static void *ht_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct ht_iterator *iter = m->private;
	struct ring_buffer_event *evt;
	u64 ts;

	(*pos)++;

	evt = ring_buffer_iter_peek(iter->buf_iter, &ts);
	if (!evt)
		return NULL;

	iter->ent = (struct hyp_entry_hdr *)&evt->array[1];
	iter->ts = ts;
	iter->ent_size = evt->array[0];
	ring_buffer_iter_advance(iter->buf_iter);

	return iter;
}

static void *ht_start(struct seq_file *m, loff_t *pos)
{
	struct ht_iterator *iter = m->private;

	if (*pos == 0) {
		ring_buffer_iter_reset(iter->buf_iter);
		(*pos)++;
		iter->ent = NULL;

		return iter;
	}

	return ht_next(m, NULL, pos);
}

static void ht_stop(struct seq_file *m, void *v) { }

static int ht_show(struct seq_file *m, void *v)
{
	struct ht_iterator *iter = v;

	if (!iter->ent) {
		seq_puts(m, "Start!\n");
	} else {
		ht_print_trace_fmt(iter);
		trace_print_seq(m, &iter->seq);
	}

	return 0;
}

static const struct seq_operations hyp_trace_ops = {
	.start	= ht_start,
	.next	= ht_next,
	.stop	= ht_stop,
	.show	= ht_show,
};

static int hyp_trace_open(struct inode *inode, struct file *file)
{
	unsigned long cpu = (unsigned long)inode->i_private;
	struct ht_iterator *iter;
	int ret = 0;

	mutex_lock(&hyp_trace_lock);

	if (!hyp_trace_buffer) {
		ret = -ENODEV;
		goto unlock;
	}

	iter = __seq_open_private(file, &hyp_trace_ops, sizeof(*iter));
	if (!iter) {
		ret = -ENOMEM;
		goto unlock;
	}

	iter->buf_iter = ring_buffer_read_prepare(hyp_trace_buffer, cpu, GFP_KERNEL);
	if (!iter->buf_iter) {
		seq_release_private(inode, file);
		ret = -ENOMEM;
		goto unlock;
	}

	ring_buffer_read_prepare_sync();
	ring_buffer_read_start(iter->buf_iter);

	hyp_trace_readers++;
unlock:
	mutex_unlock(&hyp_trace_lock);

	return ret;
}

int hyp_trace_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct ht_iterator *iter = m->private;

	ring_buffer_read_finish(iter->buf_iter);

	mutex_lock(&hyp_trace_lock);
	hyp_trace_readers--;
	mutex_lock(&hyp_trace_lock);

	return seq_release_private(inode, file);
}

static const struct file_operations hyp_trace_fops = {
	.open  = hyp_trace_open,
	.read  = seq_read,
	.llseek = seq_lseek,
	.release = hyp_trace_release,
};

/*
 * TODO: should be merged with the ring_buffer_iterator version
 */
static void *trace_buffer_peek(struct ht_iterator *iter)
{
	struct ring_buffer_event *event;

	if (ring_buffer_empty_cpu(iter->trace_buffer, iter->cpu))
		return NULL;

	event = ring_buffer_peek(iter->trace_buffer, iter->cpu, &iter->ts, &iter->lost_events);
	if (!event)
		return NULL;

	iter->ent = (struct hyp_entry_hdr *)&event->array[1];
	iter->ent_size = event->array[0];

	return iter;
}

static ssize_t
hyp_trace_pipe_read(struct file *file, char __user *ubuf,
		    size_t cnt, loff_t *ppos)
{
	struct ht_iterator *iter = (struct ht_iterator *)file->private_data;
	struct trace_buffer *trace_buffer = iter->trace_buffer;
	int ret;

	trace_seq_init(&iter->seq);
again:
	ret = ring_buffer_wait(trace_buffer, iter->cpu, 0);
	if (ret < 0)
		return ret;

	while (trace_buffer_peek(iter)) {
		unsigned long lost_events;

		ht_print_trace_fmt(iter);
		ring_buffer_consume(iter->trace_buffer, iter->cpu, NULL, &lost_events);
	}

	ret = trace_seq_to_user(&iter->seq, ubuf, cnt);
	if (ret == -EBUSY)
		goto again;

	return ret;
}

static void __poke_reader(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct ht_iterator *iter;

	iter = container_of(dwork, struct ht_iterator, poke_work);

	ring_buffer_poke(iter->trace_buffer, iter->cpu);

	schedule_delayed_work((struct delayed_work *)work,
			      msecs_to_jiffies(RB_POLL_MS));
}

static int hyp_trace_pipe_open(struct inode *inode, struct file *file)
{
	struct ht_iterator *iter;
	int ret = 0;

	mutex_lock(&hyp_trace_lock);

	if (!hyp_trace_buffer) {
		ret = -ENODEV;
		goto unlock;
	}

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (!iter) {
		ret = -ENOMEM;
		goto unlock;
	}

	iter->cpu = (unsigned long)inode->i_private;
	iter->trace_buffer = hyp_trace_buffer;

	ring_buffer_poke(iter->trace_buffer, iter->cpu);
	INIT_DELAYED_WORK(&iter->poke_work, __poke_reader);
	schedule_delayed_work(&iter->poke_work, msecs_to_jiffies(RB_POLL_MS));

	file->private_data = iter;

	hyp_trace_readers++;
unlock:
	mutex_unlock(&hyp_trace_lock);

	return ret;
}

static int hyp_trace_pipe_release(struct inode *inode, struct file *file)
{
	struct ht_iterator *iter = file->private_data;

	cancel_delayed_work_sync(&iter->poke_work);

	kfree(iter);

	mutex_lock(&hyp_trace_lock);
	hyp_trace_readers--;
	mutex_unlock(&hyp_trace_lock);

	return 0;
}

static const struct file_operations hyp_trace_pipe_fops = {
	.open		= hyp_trace_pipe_open,
	.read		= hyp_trace_pipe_read,
	.release	= hyp_trace_pipe_release,
	.llseek		= no_llseek,
};

static int __init hyp_tracing_debugfs(void)
{
	struct dentry *d, *folder;
	char trace_name[16];
	unsigned long cpu;

	folder = tracefs_create_dir("hyp", NULL);
	if (!folder) {
		pr_err("Failed to create tracefs folder for hyp\n");
		return -ENODEV;
	}

	d = tracefs_create_file("tracing_on", 0700, folder, NULL, &hyp_tracing_on_fops);
	if (!d) {
		pr_err("Failed to create file tracefs hyp/tracing_on\n");
		return -ENODEV;
	}

	for_each_possible_cpu(cpu) {
		snprintf(trace_name, sizeof(trace_name), "trace.%lu", cpu);
		d = tracefs_create_file(trace_name, 0600, folder,
				(void *)cpu,
				&hyp_trace_fops);
		if (!d)
			pr_warn("Failed create hyp/trace for CPU %lu\n", cpu);

		snprintf(trace_name, sizeof(trace_name), "trace_pipe.%lu", cpu);
		d = tracefs_create_file(trace_name, 0600, folder,
				(void *)cpu,
				&hyp_trace_pipe_fops);
		if (!d)
			pr_warn("Failed create hyp/trace for CPU %lu\n", cpu);
	}

	return 0;
}
late_initcall(hyp_tracing_debugfs);
