// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2020, The Linux Foundation. All rights reserved. */

#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/kernel.h>
#include <linux/mhi.h>

#include "qaic.h"

static ssize_t throttle_percent_show(struct device *dev,
				     struct device_attribute *a, char *buf)
{
	/*
	 * The percent the device performance is being throttled to meet
	 * the limits.  IE performance is throttled 20% to meet power/thermal/
	 * etc limits.
	 */
	return sprintf(buf, "%i\n", 50);
}

SENSOR_DEVICE_ATTR_RO(throttle_percent, throttle_percent, 0);

static ssize_t power_level_show(struct device *dev, struct device_attribute *a,
				char *buf)
{
	/*
	 * Power level the device is operating at.  What is the upper limit
	 * it is allowed to consume.
	 * 1 - full power
	 * 2 - reduced power
	 * 3 - minimal power
	 */
	return sprintf(buf, "%i\n", 1);
}

static ssize_t power_level_store(struct device *dev, struct device_attribute *a,
				 const char *buf, size_t count)
{
	long value;

	if (kstrtol(buf, 10, &value))
		return -EINVAL;

	return count;
}

SENSOR_DEVICE_ATTR_RW(power_level, power_level, 0);

static struct attribute *power_attrs[] = {
	&sensor_dev_attr_power_level.dev_attr.attr,
	&sensor_dev_attr_throttle_percent.dev_attr.attr,
	NULL,
};

static const struct attribute_group power_group = {
	.attrs = power_attrs,
};

static umode_t qaic_is_visible(const void *data, enum hwmon_sensor_types type,
			       u32 attr, int channel)
{
	switch (type) {
	case hwmon_power:
		return 0444;
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_input: /* fallthrough */
		case hwmon_temp_highest: /* fallthrough */
		case hwmon_temp_alarm:
			return 0444;
		case hwmon_temp_crit: /* fallthrough */
		case hwmon_temp_emergency:
			return 0644;
		}
	default:
		return 0;
	}
	return 0;
}

static int qaic_read(struct device *dev, enum hwmon_sensor_types type,
		     u32 attr, int channel, long *val)
{
	struct qaic_device *qdev = dev_get_drvdata(dev);

	switch (type) {
	case hwmon_power:
		*val = 1234 + qdev->next_seq_num;
		return 0;
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_alarm:
			*val = 0;
			break;
		default:
			*val = 21;
			break;
		}
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static int qaic_write(struct device *dev, enum hwmon_sensor_types type,
		      u32 attr, int channel, long val)
{
	switch (type) {
	case hwmon_temp:
		return 0;
	default:
		return -EOPNOTSUPP;
	}
}

static const struct attribute_group *special_groups[] = {
	&power_group,
	0,
};

static const struct hwmon_ops qaic_ops = {
	.is_visible = qaic_is_visible,
	.read = qaic_read,
	.write = qaic_write,
};

static const u32 qaic_config_temp[] = {
	/* board level */
	HWMON_T_INPUT | HWMON_T_HIGHEST,
	/* SoC level */
	HWMON_T_INPUT | HWMON_T_HIGHEST | HWMON_T_CRIT | HWMON_T_EMERGENCY,
	/* DDR level */
	HWMON_T_ALARM,
	0
};

static const struct hwmon_channel_info qaic_temp = {
	.type = hwmon_temp,
	.config = qaic_config_temp,
};

static const u32 qaic_config_power[] = {
	HWMON_P_INPUT, /* board level */
	0
};

static const struct hwmon_channel_info qaic_power = {
	.type = hwmon_power,
	.config = qaic_config_power,
};

static const struct hwmon_channel_info *qaic_info[] = {
	&qaic_power,
	&qaic_temp,
	NULL
};

static const struct hwmon_chip_info qaic_chip_info = {
	.ops = &qaic_ops,
	.info = qaic_info
};

static int qaic_telemetry_mhi_probe(struct mhi_device *mhi_dev,
				    const struct mhi_device_id *id)
{
	struct qaic_device *qdev;

	qdev = (struct qaic_device *)pci_get_drvdata(
					to_pci_dev(mhi_dev->mhi_cntrl->dev));

	mhi_device_set_devdata(mhi_dev, qdev);

	qdev->hwmon = hwmon_device_register_with_info(&qdev->pdev->dev, "qaic",
						      qdev, &qaic_chip_info,
						      special_groups);
	if (!qdev->hwmon)
		return -ENODEV;

	return 0;
}

static void qaic_telemetry_mhi_remove(struct mhi_device *mhi_dev)
{
	struct qaic_device *qdev;

	qdev = mhi_device_get_devdata(mhi_dev);
	hwmon_device_unregister(qdev->hwmon);
	qdev->hwmon = NULL;
}

static void qaic_telemetry_mhi_ul_xfer_cb(struct mhi_device *mhi_dev,
					  struct mhi_result *mhi_result)
{
}

static void qaic_telemetry_mhi_dl_xfer_cb(struct mhi_device *mhi_dev,
					  struct mhi_result *mhi_result)
{
}

static const struct mhi_device_id qaic_telemetry_mhi_match_table[] = {
        { .chan = "QAIC_TELEMETRY", },
        {},
};

static struct mhi_driver qaic_telemetry_mhi_driver = {
        .id_table = qaic_telemetry_mhi_match_table,
        .remove = qaic_telemetry_mhi_remove,
        .probe = qaic_telemetry_mhi_probe,
        .ul_xfer_cb = qaic_telemetry_mhi_ul_xfer_cb,
        .dl_xfer_cb = qaic_telemetry_mhi_dl_xfer_cb,
        .driver = {
                .name = "qaic_telemetry",
                .owner = THIS_MODULE,
        },
};

void qaic_telemetry_register(void)
{
	int ret;

	ret = mhi_driver_register(&qaic_telemetry_mhi_driver);
	if (ret)
		pr_debug("qaic: telemetry register failed %d\n", ret);
}

void qaic_telemetry_unregister(void)
{
	mhi_driver_unregister(&qaic_telemetry_mhi_driver);
}
