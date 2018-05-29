// SPDX-License-Identifier: GPL-2.0
// SPI to CAN driver for the Texas Instruments TCA4x5x
// Flash driver chip family
// Copyright (C) 2018 Texas Instruments Incorporated - http://www.ti.com/

#include <linux/can/core.h>
#include <linux/can/dev.h>
#include <linux/can/led.h>
#include <linux/clk.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/freezer.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/regmap.h>
#include <linux/slab.h>
#include <linux/spi/spi.h>
#include <linux/uaccess.h>
#include <linux/regulator/consumer.h>

#include "tcan4x5x.h"

struct tcan4x5x_reg {
	const char *name;
	uint16_t reg;
} tcan4x5x_regs[] = {
	{"DEV_ID0", TCAN4X5X_DEV_ID0},
	{"DEV_ID1", TCAN4X5X_DEV_ID1},
	{"REV", TCAN4X5X_REV},
	{"STATUS", TCAN4X5X_STATUS},
	{"ERROR_STATUS", TCAN4X5X_ERROR_STATUS},
	{"CONTROL", TCAN4X5X_CONTROL},
	{"CONFIG", TCAN4X5X_CONFIG},
	{"PRESCALE", TCAN4X5X_TS_PRESCALE},
	{"TEST_REG", TCAN4X5X_TEST_REG},
	{"INT_FLAGS", TCAN4X5X_INT_FLAGS},
	{"INT_EN", TCAN4X5X_INT_EN},
	{"MCAN_INT_FLAG", TCAN4X5X_MCAN_INT_FLAG},
	{"MCAN_INT_EN", TCAN4X5X_MCAN_INT_EN},
	{"MCAN_CCCR", TCAN4X5X_MCAN_CCCR},
	{"MCAN_ECR", TCAN4X5X_MCAN_ECR},
	{"TX_ELM_SZ", TCAN4X5X_MCAN_TXESC},
	{"DBTP", TCAN4X5X_MCAN_DBTP},
	{"NBTP", TCAN4X5X_MCAN_NBTP},
	{"PROTOCAL_STATUS", TCAN4X5X_MCAN_PSR},
	{"TDCR", TCAN4X5X_MCAN_TDCR},
	{"TXBAR", TCAN4X5X_MCAN_TXBAR},
	{"ILE", TCAN4X5X_MCAN_ILE},
	{"RXESC", TCAN4X5X_MCAN_RXESC},
	{"CREL", TCAN4X5X_MCAN_CREL},
	{"TXBC", TCAN4X5X_MCAN_TXBC},
	{"READ", 0xffff},
};

static ssize_t tcan4x5x_registers_show(struct device *dev,
					    struct device_attribute *attr,
					    char *buf)
{
	struct tcan4x5x_priv *data = dev_get_drvdata(dev);
	unsigned i, n, reg_count;
	unsigned int read_buf;

	reg_count = sizeof(tcan4x5x_regs) / sizeof(tcan4x5x_regs[0]);
	for (i = 0, n = 0; i < reg_count; i++) {
		if (tcan4x5x_regs[i].reg != 0xffff) {
			regmap_read(data->regmap, tcan4x5x_regs[i].reg, &read_buf);
			n += scnprintf(buf + n, PAGE_SIZE - n, "%s 0x%08X\n",
				       tcan4x5x_regs[i].name, read_buf);
		}
	}
	return n;
}

static ssize_t tcan4x5x_registers_store(struct device *dev,
					     struct device_attribute *attr,
					     const char *buf, size_t count)
{
	struct tcan4x5x_priv *data = dev_get_drvdata(dev);
	unsigned i, reg_count, value;
	int error = 0;
	char name[30];

	if (count >= 30) {
		pr_err("%s:input too long\n", __func__);
		return -1;
	}

	if (sscanf(buf, "%s %x", name, &value) != 2) {
		pr_err("%s:unable to parse input\n", __func__);
		return -1;
	}

	reg_count = sizeof(tcan4x5x_regs) / sizeof(tcan4x5x_regs[0]);
	for (i = 0; i < reg_count; i++) {
		if (!strcmp(name, tcan4x5x_regs[i].name)) {
			if (tcan4x5x_regs[i].reg == 0xffff) {
				tcan4x5x_hw_rx(data);
				return count;
			} else {
				regcache_cache_only(data->regmap, false);
				error = regmap_write(data->regmap,
						 tcan4x5x_regs[i].reg, value);
				if (error) {
					pr_err("%s:Failed to write %s\n",
					       __func__, name);
					return -1;
				}
				return count;
			}
		}
	}
	pr_err("%s:no such register %s\n", __func__, name);
	return -1;
}

static DEVICE_ATTR(registers, S_IWUSR | S_IRUGO,
		   tcan4x5x_registers_show, tcan4x5x_registers_store);

static struct attribute *tcan4x5x_attrs[] = {
	&dev_attr_registers.attr,
	NULL
};

static const struct attribute_group tcan4x5x_attr_group = {
	.attrs = tcan4x5x_attrs,
};

int tcan4x5x_init_debug(struct tcan4x5x_priv *tcan4x5x)
{
	int ret;
	struct tcan4x5x_priv *dbg_tcan4x5x;

	printk("%s: Init debug\n", __func__);
	dbg_tcan4x5x = tcan4x5x;

	ret =
	    sysfs_create_group(&dbg_tcan4x5x->spi->dev.kobj,
			       &tcan4x5x_attr_group);
	if (ret < 0)
		dev_err(&dbg_tcan4x5x->spi->dev, "Failed to create sysfs: %d\n",
			ret);

	return ret;
}
EXPORT_SYMBOL_GPL(tcan4x5x_init_debug);

MODULE_DESCRIPTION("TCAN4x5x debug");
MODULE_AUTHOR("Dan Murphy");
MODULE_LICENSE("GPL");
