// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021 Google LLC
 * Author: Floris Westermann <westermann@google.com>
 */

#include <linux/cpufreq.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/slab.h>

#define FREQ_TABLE_MIN_FREQ	128
#define FREQ_TABLE_MAX_FREQ	1024
#define FREQ_TABLE_STEP		128
#define NUM_ENTRIES		((FREQ_TABLE_MAX_FREQ - FREQ_TABLE_MIN_FREQ)\
				/ FREQ_TABLE_STEP + 1)

static unsigned int __iomem *base;

static const struct of_device_id virt_cpufreq_match[] = {
	{ .compatible = "pkvm,virt-cpufreq"},
	{}
};
MODULE_DEVICE_TABLE(of, virt_cpufreq_match);

static int virt_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
	struct cpufreq_frequency_table *table;
	int i;

	// Initialize frequency table.
	table = kcalloc(NUM_ENTRIES + 1, sizeof(struct cpufreq_frequency_table), GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	for (i = 0; i < NUM_ENTRIES; ++i)
		table[i].frequency = FREQ_TABLE_MIN_FREQ + FREQ_TABLE_STEP * i;

	table[NUM_ENTRIES].frequency = CPUFREQ_TABLE_END;
	policy->freq_table = table;

	return 0;
}

static int virt_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
	kfree(policy->freq_table);
	return 0;
}

static int virt_cpufreq_target_index(struct cpufreq_policy *policy,
		unsigned int index)
{
	u32 frq = policy->freq_table[index].frequency;

	writel_relaxed(frq, base);

	return 0;
}

static struct cpufreq_driver cpufreq_virt_driver = {
	.name		= "virt-cpufreq",
	.init		= virt_cpufreq_cpu_init,
	.exit		= virt_cpufreq_cpu_exit,
	.verify		= cpufreq_generic_frequency_table_verify,
	.target_index	= virt_cpufreq_target_index,
	.attr		= cpufreq_generic_attr,
};


static int virt_cpufreq_driver_probe(struct platform_device *pdev)
{
	int ret;
	struct resource *res;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "failed to get mem resource\n");
		return -ENODEV;
	}
	if (resource_size(res) < 4) {
		dev_err(&pdev->dev, "resource to small %lld\n", resource_size(res));
		return -EINVAL;
	}
	if (!request_mem_region(res->start, resource_size(res), res->name)) {
		dev_err(&pdev->dev, "failed to request resource %pR\n", res);
		return -EBUSY;
	}


	base = ioremap(res->start, resource_size(res));
	if (!base) {
		dev_err(&pdev->dev, "failed to map resource %pR\n", res);
		ret = -ENOMEM;
		goto rel_mem_reg;
	}
	cpufreq_virt_driver.driver_data = pdev;

	ret = cpufreq_register_driver(&cpufreq_virt_driver);
	if (ret) {
		dev_err(&pdev->dev, "Virt CPUFreq driver failed to register: %d\n", ret);
		goto rel_mem_reg;
	} else {
		dev_dbg(&pdev->dev, "Virt CPUFreq driver initialized\n");
	}

	return 0;
rel_mem_reg:
	release_mem_region(res->start, resource_size(res));
	return ret;
}

static int virt_cpufreq_driver_remove(struct platform_device *pdev)
{
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	if (!res) {
		dev_err(&pdev->dev, "failed to get mem resource\n");
		return -ENODEV;
	}
	iounmap(base);
	release_mem_region(res->start, resource_size(res));
	return cpufreq_unregister_driver(&cpufreq_virt_driver);
}

static struct platform_driver virt_cpufreq_driver = {
	.probe = virt_cpufreq_driver_probe,
	.remove = virt_cpufreq_driver_remove,
	.driver = {
		.name = "virt-cpufreq",
		.of_match_table = virt_cpufreq_match,
	},
};

static int __init virt_cpufreq_init(void)
{
	return platform_driver_register(&virt_cpufreq_driver);
}

static void __exit virt_cpufreq_exit(void)
{
	platform_driver_unregister(&virt_cpufreq_driver);
}

module_init(virt_cpufreq_init);
module_exit(virt_cpufreq_exit);

MODULE_AUTHOR("Floris Westermann <westermann@google.de>");
MODULE_DESCRIPTION("Virtual cpufreq driver");
MODULE_LICENSE("GPL");

