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
#include <linux/pm_opp.h>
#include <linux/slab.h>

struct private_data {
	struct list_head node;

	cpumask_var_t cpus;
	struct device *cpu_dev;
	struct opp_table *opp_table;
	struct cpufreq_frequency_table *freq_table;
	bool have_static_opps;
};

struct message {
	union {
		struct {
			u32 frq;
		} fields __packed;
		u32 bits;
	};
} __packed;

static LIST_HEAD(priv_list);
static u32 __iomem *base;

static struct private_data *virt_cpufreq_find_data(int cpu)
{
	struct private_data *priv;

	list_for_each_entry(priv, &priv_list, node)
		if (cpumask_test_cpu(cpu, priv->cpus))
			return priv;

	return NULL;
}

static int virt_cpufreq_target_index(struct cpufreq_policy *policy,
		unsigned int index)
{
	struct message msg = {
		.fields.frq = policy->freq_table[index].frequency,
	};

	writel_relaxed(msg.bits, base);

	return 0;
}

static const struct of_device_id virt_cpufreq_match[] = {
	{ .compatible = "pkvm,virt-cpufreq"},
	{}
};
MODULE_DEVICE_TABLE(of, virt_cpufreq_match);

static int virt_cpufreq_cpu_init(struct cpufreq_policy *policy)
{
	struct private_data *priv;
	struct device *cpu_dev;

	priv = virt_cpufreq_find_data(policy->cpu);
	if (!priv) {
		pr_err("failed to find data for cpu%d\n", policy->cpu);
		return -ENODEV;
	}
	cpu_dev = priv->cpu_dev;

	cpumask_copy(policy->cpus, priv->cpus);
	policy->driver_data = priv;
	policy->freq_table = priv->freq_table;
	policy->dvfs_possible_from_any_cpu = false;

	dev_pm_opp_of_register_em(cpu_dev, policy->cpus);

	return 0;
}

static int virt_cpufreq_cpu_exit(struct cpufreq_policy *policy)
{
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

static int cpufreq_virt_early_init(struct device *dev, int cpu)
{
	struct private_data *priv;
	struct device *cpu_dev;
	bool fallback = false;
	int ret;

	if (virt_cpufreq_find_data(cpu))
		return 0;

	cpu_dev = get_cpu_device(cpu);
	if (!cpu_dev)
		return -EPROBE_DEFER;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	if (!alloc_cpumask_var(&priv->cpus, GFP_KERNEL))
		return  -ENOMEM;

	cpumask_set_cpu(cpu, priv->cpus);
	priv->cpu_dev = cpu_dev;

	/* Get OPP-sharing information from "operating-points-v2" bindings */
	ret = dev_pm_opp_of_get_sharing_cpus(cpu_dev, priv->cpus);
	if (ret) {
		if (ret != -ENOENT)
			goto out;

		/*
		 * operating-points-v2 not supported, fallback to all CPUs share
		 * OPP for backward compatibility if the platform hasn't set
		 * sharing CPUs.
		 */
		if (dev_pm_opp_get_sharing_cpus(cpu_dev, priv->cpus))
			fallback = true;
	}

	ret = dev_pm_opp_of_cpumask_add_table(priv->cpus);
	if (!ret)
		priv->have_static_opps = true;
	else if (ret == -EPROBE_DEFER)
		goto out;

	/*
	 * The OPP table must be initialized, statically or dynamically, by this
	 * point.
	 */
	ret = dev_pm_opp_get_opp_count(cpu_dev);
	if (ret <= 0) {
		dev_err(cpu_dev, "OPP table can't be empty\n");
		ret = -ENODEV;
		goto out;
	}

	if (fallback) {
		cpumask_setall(priv->cpus);
		ret = dev_pm_opp_set_sharing_cpus(cpu_dev, priv->cpus);
		if (ret)
			dev_err(cpu_dev, "%s: failed to mark OPPs as shared: %d\n",
				__func__, ret);
	}

	ret = dev_pm_opp_init_cpufreq_table(cpu_dev, &priv->freq_table);
	if (ret) {
		dev_err(cpu_dev, "failed to init cpufreq table: %d\n", ret);
		goto out;
	}

	list_add(&priv->node, &priv_list);
	return 0;

out:
	if (priv->have_static_opps)
		dev_pm_opp_of_cpumask_remove_table(priv->cpus);
	dev_pm_opp_put_regulators(priv->opp_table);
	free_cpumask_var(priv->cpus);
	return ret;
}

static void cpufreq_virt_release(void)
{
	struct private_data *priv, *tmp;

	list_for_each_entry_safe(priv, tmp, &priv_list, node) {
		dev_pm_opp_free_cpufreq_table(priv->cpu_dev, &priv->freq_table);
		if (priv->have_static_opps)
			dev_pm_opp_of_cpumask_remove_table(priv->cpus);
		dev_pm_opp_put_regulators(priv->opp_table);
		free_cpumask_var(priv->cpus);
		list_del(&priv->node);
	}
}

static int virt_cpufreq_driver_probe(struct platform_device *pdev)
{
	struct resource *res;
	int ret, cpu;

	for_each_possible_cpu(cpu) {
		ret = cpufreq_virt_early_init(&pdev->dev, cpu);
		if (ret)
			goto rel_cpufreq;
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "failed to get mem resource\n");
		return -ENODEV;
	}
	if (resource_size(res) < sizeof(struct message)) {
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
rel_cpufreq:
	cpufreq_virt_release();
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
	cpufreq_unregister_driver(&cpufreq_virt_driver);
	cpufreq_virt_release();
	return 0;
}

static struct platform_driver virt_cpufreq_driver = {
	.probe = virt_cpufreq_driver_probe,
	.remove = virt_cpufreq_driver_remove,
	.driver = {
		.name = "virt-cpufreq",
		.of_match_table = virt_cpufreq_match,
	},
};

module_platform_driver(virt_cpufreq_driver);

MODULE_AUTHOR("Floris Westermann <westermann@google.de>");
MODULE_DESCRIPTION("Virtual cpufreq driver");
MODULE_LICENSE("GPL");

