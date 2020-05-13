// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2020, The Linux Foundation. All rights reserved. */

#include <asm/byteorder.h>
#include <linux/completion.h>
#include <linux/hwmon.h>
#include <linux/hwmon-sysfs.h>
#include <linux/kernel.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mhi.h>
#include <linux/mutex.h>
#include <linux/srcu.h>
#include <linux/workqueue.h>

#include "qaic.h"

#ifdef CONFIG_QAIC_HWMON

#define MAGIC		0x55AA
#define VERSION		0x1
#define RESP_TIMEOUT	1 * HZ

enum cmds {
	CMD_THERMAL_SOC_TEMP,
	CMD_THERMAL_SOC_MAX_TEMP,
	CMD_THERMAL_BOARD_TEMP,
	CMD_THERMAL_BOARD_MAX_TEMP,
	CMD_THERMAL_DDR_TEMP,
	CMD_THERMAL_WARNING_TEMP,
	CMD_THERMAL_SHUTDOWN_TEMP,
	CMD_CURRENT_TDP,
	CMD_BOARD_POWER,
	CMD_POWER_STATE,
	CMD_POWER_MAX,
	CMD_THROTTLE_PERCENT,
	CMD_THROTTLE_TIME,
};

enum cmd_type {
	TYPE_READ,  /* read value from device */
	TYPE_WRITE, /* write value to device */
};

enum msg_type {
	MSG_PUSH, /* async push from device */
	MSG_REQ,  /* sync request to device */
	MSG_RESP, /* sync response from device */
};

struct telemetry_data {
	u8  cmd;
	u8  cmd_type;
	u8  status;
	u64 val;
} __packed;

struct telemetry_header {
	u16 magic;
	u16 ver;
	u32 seq_num;
	u8  type;
	u8  id;
	u16 len;
} __packed;

struct telemetry_msg { /* little endian encoded */
	struct telemetry_header hdr;
	struct telemetry_data data;
} __packed;

struct wrapper_msg {
	struct kref ref_count;
	struct telemetry_msg msg;
};

struct xfer_queue_elem {
	struct list_head list;
	u32 seq_num;
	struct completion xfer_done;
	void *buf;
};

struct resp_work {
	struct work_struct work;
	struct qaic_device *qdev;
	void *buf;
};

static void free_wrapper(struct kref *ref)
{
	struct wrapper_msg *wrapper = container_of(ref, struct wrapper_msg,
						   ref_count);

	kfree(wrapper);
}

static int telemetry_request(struct qaic_device *qdev, u8 cmd, u8 cmd_type,
			     long *val)
{
	struct wrapper_msg *wrapper;
	struct xfer_queue_elem elem;
	struct telemetry_msg *resp;
	struct telemetry_msg *req;
	long ret = 0;

	wrapper = kzalloc(sizeof(*wrapper), GFP_KERNEL);
	if (!wrapper)
		return -ENOMEM;

	kref_init(&wrapper->ref_count);
	req = &wrapper->msg;

	ret = mutex_lock_interruptible(&qdev->tele_mutex);
	if (ret)
		goto free_req;

	req->hdr.magic = cpu_to_le16(MAGIC);
	req->hdr.ver = cpu_to_le16(VERSION);
	req->hdr.seq_num = cpu_to_le32(qdev->tele_next_seq_num++);
	req->hdr.type = MSG_REQ;
	req->hdr.id = 0;
	req->hdr.len = cpu_to_le16(sizeof(req->data));

	req->data.cmd = cmd;
	req->data.cmd_type = cmd_type;
	req->data.status = 0;
	if (cmd_type == TYPE_READ)
		req->data.val = cpu_to_le64(0);
	else
		req->data.val = cpu_to_le64(*val);

	elem.seq_num = qdev->tele_next_seq_num - 1;
	elem.buf = NULL;
	init_completion(&elem.xfer_done);
	if (likely(!qdev->tele_lost_buf)) {
		resp = kmalloc(sizeof(*resp), GFP_KERNEL);
		if (!resp) {
			mutex_unlock(&qdev->tele_mutex);
			ret = -ENOMEM;
			goto free_req;
		}

		ret = mhi_queue_transfer(qdev->tele_ch, DMA_FROM_DEVICE,
					 resp, sizeof(*resp), MHI_EOT);
		if (ret) {
			mutex_unlock(&qdev->tele_mutex);
			goto free_resp;
		}
	} else {
		/*
		 * we lost a buffer because we queued a recv buf, but then
		 * queuing the corresponding tx buf failed.  To try to avoid
		 * a memory leak, lets reclaim it and use it for this
		 * transaction.
		 */
		qdev->tele_lost_buf = false;
	}

	kref_get(&wrapper->ref_count);
	ret = mhi_queue_transfer(qdev->tele_ch, DMA_TO_DEVICE, req,
				 sizeof(*req), MHI_EOT);
	if (ret) {
		qdev->tele_lost_buf = true;
		kref_put(&wrapper->ref_count, free_wrapper);
		mutex_unlock(&qdev->tele_mutex);
		goto free_req;
	}

	list_add_tail(&elem.list, &qdev->tele_xfer_list);
	mutex_unlock(&qdev->tele_mutex);

	ret = wait_for_completion_interruptible_timeout(&elem.xfer_done,
								RESP_TIMEOUT);
	/*
	 * not using _interruptable because we have to cleanup or we'll
	 * likely cause memory corruption
	 */
	mutex_lock(&qdev->tele_mutex);
	if (!list_empty(&elem.list))
		list_del(&elem.list);
	if (!ret && !elem.buf)
		ret = -ETIMEDOUT;
	else if (ret > 0 && !elem.buf)
		ret = -EIO;
	mutex_unlock(&qdev->tele_mutex);

	resp = elem.buf;

	if (ret < 0)
		goto free_resp;

	if (le16_to_cpu(resp->hdr.magic) != MAGIC ||
	    le16_to_cpu(resp->hdr.ver) != VERSION ||
	    resp->hdr.type != MSG_RESP ||
	    resp->hdr.id != 0 ||
	    le16_to_cpu(resp->hdr.len) != sizeof(resp->data) ||
	    resp->data.cmd != cmd ||
	    resp->data.cmd_type != cmd_type ||
	    resp->data.status) {
		ret = -EINVAL;
		goto free_resp;
	}

	if (cmd_type == TYPE_READ)
		*val = le64_to_cpu(resp->data.val);

	ret = 0;

free_resp:
	kfree(resp);
free_req:
	kref_put(&wrapper->ref_count, free_wrapper);

	return ret;
}

static ssize_t throttle_percent_show(struct device *dev,
				     struct device_attribute *a, char *buf)
{
	struct qaic_device *qdev = dev_get_drvdata(dev);
	long val = 0;
	int rcu_id;
	int ret;

	rcu_id = srcu_read_lock(&qdev->dev_lock);
	if (qdev->in_reset) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return -ENODEV;
	}

	ret = telemetry_request(qdev, CMD_THROTTLE_PERCENT, TYPE_READ, &val);

	if (ret) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return ret;
	}

	/*
	 * The percent the device performance is being throttled to meet
	 * the limits.  IE performance is throttled 20% to meet power/thermal/
	 * etc limits.
	 */
	srcu_read_unlock(&qdev->dev_lock, rcu_id);
	return sprintf(buf, "%i\n", (int)val);
}

SENSOR_DEVICE_ATTR_RO(throttle_percent, throttle_percent, 0);

static ssize_t power_level_show(struct device *dev, struct device_attribute *a,
				char *buf)
{
	struct qaic_device *qdev = dev_get_drvdata(dev);
	long val = 0;
	int rcu_id;
	int ret;

	rcu_id = srcu_read_lock(&qdev->dev_lock);
	if (qdev->in_reset) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return -ENODEV;
	}

	ret = telemetry_request(qdev, CMD_POWER_STATE, TYPE_READ, &val);

	if (ret) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return ret;
	}

	/*
	 * Power level the device is operating at.  What is the upper limit
	 * it is allowed to consume.
	 * 1 - full power
	 * 2 - reduced power
	 * 3 - minimal power
	 */
	srcu_read_unlock(&qdev->dev_lock, rcu_id);
	return sprintf(buf, "%i\n", (int)val);
}

static ssize_t power_level_store(struct device *dev, struct device_attribute *a,
				 const char *buf, size_t count)
{
	struct qaic_device *qdev = dev_get_drvdata(dev);
	int rcu_id;
	long val;
	int ret;

	rcu_id = srcu_read_lock(&qdev->dev_lock);
	if (qdev->in_reset) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return -ENODEV;
	}

	if (kstrtol(buf, 10, &val)) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return -EINVAL;
	}

	ret = telemetry_request(qdev, CMD_POWER_STATE, TYPE_WRITE, &val);

	if (ret) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return ret;
	}

	srcu_read_unlock(&qdev->dev_lock, rcu_id);
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
		switch (attr) {
		case hwmon_power_max:
			return 0644;
		default:
			return 0444;
		}
		break;
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
		break;
	default:
		return 0;
	}
	return 0;
}

static int qaic_read(struct device *dev, enum hwmon_sensor_types type,
		     u32 attr, int channel, long *val)
{
	struct qaic_device *qdev = dev_get_drvdata(dev);
	int rcu_id;
	int ret = -EOPNOTSUPP;
	u8 cmd;

	rcu_id = srcu_read_lock(&qdev->dev_lock);
	if (qdev->in_reset) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return -ENODEV;
	}

	switch (type) {
	case hwmon_power:
		switch (attr) {
		case hwmon_power_max:
			ret = telemetry_request(qdev, CMD_CURRENT_TDP,
						TYPE_READ, val);
			*val *= 1000000;
			goto exit;
		case hwmon_power_input:
			ret = telemetry_request(qdev, CMD_BOARD_POWER,
						TYPE_READ, val);
			*val *= 1000000;
			goto exit;
		default:
			goto exit;
		}
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_crit:
			ret = telemetry_request(qdev, CMD_THERMAL_WARNING_TEMP,
						TYPE_READ, val);
			*val *= 1000000;
			goto exit;
		case hwmon_temp_emergency:
			ret = telemetry_request(qdev, CMD_THERMAL_SHUTDOWN_TEMP,
						TYPE_READ, val);
			*val *= 1000000;
			goto exit;
		case hwmon_temp_alarm:
			ret = telemetry_request(qdev, CMD_THERMAL_DDR_TEMP,
						TYPE_READ, val);
			goto exit;
		case hwmon_temp_input:
			if (channel == 0)
				cmd = CMD_THERMAL_BOARD_TEMP;
			else if (channel == 1)
				cmd = CMD_THERMAL_SOC_TEMP;
			else
				goto exit;
			ret = telemetry_request(qdev, cmd, TYPE_READ, val);
			*val *= 1000000;
			goto exit;
		case hwmon_temp_highest:
			if (channel == 0)
				cmd = CMD_THERMAL_BOARD_MAX_TEMP;
			else if (channel == 1)
				cmd = CMD_THERMAL_SOC_MAX_TEMP;
			else
				goto exit;
			ret = telemetry_request(qdev, cmd, TYPE_READ, val);
			*val *= 1000000;
			goto exit;
		default:
			goto exit;
		}
	default:
		goto exit;
	}

exit:
	srcu_read_unlock(&qdev->dev_lock, rcu_id);
	return ret;
}

static int qaic_write(struct device *dev, enum hwmon_sensor_types type,
		      u32 attr, int channel, long val)
{
	struct qaic_device *qdev = dev_get_drvdata(dev);
	int rcu_id;
	int ret = -EOPNOTSUPP;

	rcu_id = srcu_read_lock(&qdev->dev_lock);
	if (qdev->in_reset) {
		srcu_read_unlock(&qdev->dev_lock, rcu_id);
		return -ENODEV;
	}

	switch (type) {
	case hwmon_power:
		switch (attr) {
		case hwmon_power_max:
			val /= 1000000;
			ret = telemetry_request(qdev, CMD_CURRENT_TDP,
						TYPE_WRITE, &val);
			goto exit;
		default:
			goto exit;
		}
	case hwmon_temp:
		switch (attr) {
		case hwmon_temp_crit:
			val /= 1000000;
			ret = telemetry_request(qdev, CMD_THERMAL_WARNING_TEMP,
						TYPE_WRITE, &val);
			goto exit;
		case hwmon_temp_emergency:
			val /= 1000000;
			ret = telemetry_request(qdev, CMD_THERMAL_SHUTDOWN_TEMP,
						TYPE_WRITE, &val);
			goto exit;
		default:
			goto exit;
		}
	default:
		goto exit;
	}

exit:
	srcu_read_unlock(&qdev->dev_lock, rcu_id);
	return ret;
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
	HWMON_P_INPUT | HWMON_P_MAX, /* board level */
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
	int ret;

	qdev = (struct qaic_device *)pci_get_drvdata(
					to_pci_dev(mhi_dev->mhi_cntrl->dev));

	mhi_device_set_devdata(mhi_dev, qdev);
	qdev->tele_ch = mhi_dev;
	ret = mhi_prepare_for_transfer(qdev->tele_ch);

	if (ret)
		return ret;

	qdev->hwmon = hwmon_device_register_with_info(&qdev->pdev->dev, "qaic",
						      qdev, &qaic_chip_info,
						      special_groups);
	if (!qdev->hwmon) {
		mhi_unprepare_from_transfer(qdev->tele_ch);
		return -ENODEV;
	}

	return 0;
}

static void qaic_telemetry_mhi_remove(struct mhi_device *mhi_dev)
{
	struct qaic_device *qdev;

	qdev = mhi_device_get_devdata(mhi_dev);
	hwmon_device_unregister(qdev->hwmon);
	mhi_unprepare_from_transfer(qdev->tele_ch);
	qdev->tele_ch = NULL;
	qdev->hwmon = NULL;
}

static void resp_worker(struct work_struct *work)
{
	struct resp_work *resp = container_of(work, struct resp_work, work);
	struct qaic_device *qdev = resp->qdev;
	struct telemetry_msg *msg = resp->buf;
	struct xfer_queue_elem *elem;
	struct xfer_queue_elem *i;
	bool found = false;

	if (msg->hdr.magic != MAGIC) {
		kfree(msg);
		kfree(resp);
		return;
	}

	mutex_lock(&qdev->tele_mutex);
	list_for_each_entry_safe(elem, i, &qdev->tele_xfer_list, list) {
		if (elem->seq_num == le32_to_cpu(msg->hdr.seq_num)) {
			found = true;
			list_del_init(&elem->list);
			elem->buf = msg;
			complete_all(&elem->xfer_done);
			break;
		}
	}
	mutex_unlock(&qdev->tele_mutex);

	if (!found)
		/* request must have timed out, drop packet */
		kfree(msg);

	kfree(resp);
}

static void qaic_telemetry_mhi_ul_xfer_cb(struct mhi_device *mhi_dev,
					  struct mhi_result *mhi_result)
{
	struct telemetry_msg *msg = mhi_result->buf_addr;
	struct wrapper_msg *wrapper = container_of(msg, struct wrapper_msg,
						   msg);

	kref_put(&wrapper->ref_count, free_wrapper);
}

static void qaic_telemetry_mhi_dl_xfer_cb(struct mhi_device *mhi_dev,
					  struct mhi_result *mhi_result)
{
	struct qaic_device *qdev = mhi_device_get_devdata(mhi_dev);
	struct telemetry_msg *msg = mhi_result->buf_addr;
	struct resp_work *resp;

	if (mhi_result->transaction_status) {
		kfree(msg);
		return;
	}

	resp = kmalloc(sizeof(*resp), GFP_ATOMIC);
	if (!resp) {
		pci_err(qdev->pdev, "dl_xfer_cb alloc fail, dropping message\n");
		kfree(msg);
		return;
	}

	INIT_WORK(&resp->work, resp_worker);
	resp->qdev = qdev;
	resp->buf = msg;
	queue_work(qdev->tele_wq, &resp->work);
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

void wake_all_telemetry(struct qaic_device *qdev)
{
	struct xfer_queue_elem *elem;
	struct xfer_queue_elem *i;

	mutex_lock(&qdev->tele_mutex);
	list_for_each_entry_safe(elem, i, &qdev->tele_xfer_list, list) {
		list_del_init(&elem->list);
		complete_all(&elem->xfer_done);
	}
	qdev->tele_lost_buf = false;
	mutex_unlock(&qdev->tele_mutex);
}

#else

void qaic_telemetry_register(void)
{
}

void qaic_telemetry_unregister(void)
{
}

void wake_all_telemetry(struct qaic_device *qdev)
{
}

#endif /* CONFIG_QAIC_HWMON */
