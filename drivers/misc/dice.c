// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 - Google LLC
 * Author: David Brazdil <dbrazdil@google.com>
 *
 * Driver for Open Profile for DICE.
 *
 * This driver takes ownership of a reserved memory region containing secrets
 * derived following the Open Profile for DICE. The contents of the memory
 * region are not interpreted by the kernel but can be mapped into a userspace
 * process via a misc device. The memory region can also be wiped, removing
 * the secrets from memory.
 *
 * Userspace can access the data by (w/o error handling):
 *
 *     int fd = open("/dev/dice", O_RDONLY | O_CLOEXEC);
 *     size_t size = ioctl(fd, DICE_GET_SIZE);
 *     void *data = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, 0);
 *     ioctl(fd, DICE_WIPE);
 *     close(fd);
 */

#include <linux/dice.h>
#include <linux/io.h>
#include <linux/miscdevice.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/of_reserved_mem.h>
#include <linux/platform_device.h>

static int dice_mmap(struct file *filp, struct vm_area_struct *vma);
static long dice_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);

static const struct file_operations dice_fops = {
	.mmap = dice_mmap,
	.unlocked_ioctl = dice_ioctl,
};

static struct miscdevice dice_misc = {
	.name	= "dice",
	.minor	= MISC_DYNAMIC_MINOR,
	.fops	= &dice_fops,
	.mode	= 0400,
};

static struct reserved_mem *dice_rmem;
static DEFINE_SPINLOCK(dice_lock);

static int dice_mmap(struct file *filp, struct vm_area_struct *vma)
{
	/* Do not allow userspace to modify the underlying data. */
	if ((vma->vm_flags & VM_WRITE) && (vma->vm_flags & VM_SHARED))
		return -EPERM;

	/* Create write-combine mapping so all clients observe a wipe. */
	vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);
	vma->vm_flags |= VM_DONTCOPY | VM_DONTDUMP;
	return vm_iomap_memory(vma, dice_rmem->base, dice_rmem->size);
}

static int dice_wipe(void)
{
	void *kaddr;

	spin_lock(&dice_lock);
	kaddr = devm_memremap(dice_misc.this_device, dice_rmem->base,
			      dice_rmem->size, MEMREMAP_WC);
	if (IS_ERR(kaddr)) {
		spin_unlock(&dice_lock);
		return PTR_ERR(kaddr);
	}

	memzero_explicit(kaddr, dice_rmem->size);
	devm_memunmap(dice_misc.this_device, kaddr);
	spin_unlock(&dice_lock);
	return 0;
}

static long dice_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	switch (cmd) {
	case DICE_GET_SIZE:
		/* Checked against INT_MAX in dice_probe(). */
		return dice_rmem->size;
	case DICE_WIPE:
		return dice_wipe();
	}

	return -ENOIOCTLCMD;
}

static int __init dice_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *rmem_np;
	struct reserved_mem *rmem;
	int ret;

	if (dice_rmem) {
		dev_err(dev, "only one instance of device allowed\n");
		return -EBUSY;
	}

	rmem_np = of_parse_phandle(dev->of_node, "memory-region", 0);
	if (!rmem_np) {
		dev_err(dev, "missing 'memory-region' property\n");
		return -EINVAL;
	}

	rmem = of_reserved_mem_lookup(rmem_np);
	of_node_put(rmem_np);
	if (!rmem) {
		dev_err(dev, "failed to lookup reserved memory\n");
		return -EINVAL;
	}

	if (!PAGE_ALIGNED(rmem->base) || !PAGE_ALIGNED(rmem->size)) {
		dev_err(dev, "memory region must be page-aligned\n");
		return -EINVAL;
	}

	if (!rmem->size || (rmem->size > INT_MAX)) {
		dev_err(dev, "invalid memory region size\n");
		return -EINVAL;
	}

	dice_misc.parent = dev;
	ret = misc_register(&dice_misc);
	if (ret) {
		dev_err(dev, "failed to register misc device: %d\n", ret);
		return ret;
	}

	dice_rmem = rmem;
	return 0;
}

static int dice_remove(struct platform_device *pdev)
{
	misc_deregister(&dice_misc);
	dice_rmem = NULL;
	return 0;
}

static const struct of_device_id dice_of_match[] = {
	{ .compatible = "google,dice" },
	{},
};

static struct platform_driver dice_driver = {
	.remove = dice_remove,
	.driver = {
		.name = "dice",
		.of_match_table = dice_of_match,
	},
};

module_platform_driver_probe(dice_driver, dice_probe);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("David Brazdil <dbrazdil@google.com>");
