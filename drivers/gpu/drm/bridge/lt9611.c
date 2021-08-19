// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2020-2021, The Linux Foundation. All rights reserved.
 */

#define pr_fmt(fmt) "%s: " fmt, __func__

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>
#include <linux/fs.h>
#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/gpio.h>
#include <linux/interrupt.h>
#include <linux/component.h>
#include <linux/workqueue.h>
#include <linux/of_gpio.h>
#include <linux/of_graph.h>
#include <linux/of_irq.h>
#include <linux/regulator/consumer.h>
#include <linux/firmware.h>
#include <linux/hdmi.h>
#include <drm/drmP.h>
#include <drm/drm_atomic.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_edid.h>
#include <drm/drm_mipi_dsi.h>
#include <drm/drm_crtc_helper.h>
#include <linux/string.h>

#include <linux/kthread.h>

struct lt9611 *pStdata;

#define CFG_HPD_INTERRUPTS BIT(0)
#define CFG_EDID_INTERRUPTS BIT(1)
#define CFG_CEC_INTERRUPTS BIT(2)
#define CFG_VID_CHK_INTERRUPTS BIT(3)

#define EDID_SEG_SIZE 256
#define EDID_ERR_RETRY 5
#define READ_BUF_MAX_SIZE 128
#define WRITE_BUF_MAX_SIZE 128
#define HPD_UEVENT_BUFFER_SIZE 32
#define EDID_TIMEOUT_MS 2000
#define VIC_FIX_4k30 95

struct lt9611_reg_cfg {
	u8 reg;
	u8 val;
};

struct lt9611_vreg {
	struct regulator *vreg; /* vreg handle */
	char vreg_name[32];
	int min_voltage;
	int max_voltage;
	int enable_load;
	int disable_load;
	int pre_on_sleep;
	int post_on_sleep;
	int pre_off_sleep;
	int post_off_sleep;
};

struct lt9611_video_cfg {
	u32 h_active;
	u32 h_front_porch;
	u32 h_pulse_width;
	u32 h_back_porch;
	bool h_polarity;
	u32 v_active;
	u32 v_front_porch;
	u32 v_pulse_width;
	u32 v_back_porch;
	bool v_polarity;
	u32 pclk_khz;
	bool interlaced;
	u32 vic;
	enum hdmi_picture_aspect ar;
	u32 num_of_lanes;
	u32 num_of_intfs;
	u8 scaninfo;
};

struct lt9611_vid_cfg {
	u32 h_total;
	u32 h_act;
	u32 hpw;
	u32 hfp;
	u32 hss;
	u32 v_total;
	u32 v_act;
	u32 vpw;
	u32 vfp;
	u32 vss;
};

struct lt9611 {
	struct device *dev;
	struct drm_bridge bridge;

	struct device_node *host_node;
	struct mipi_dsi_device *dsi;
	struct drm_connector connector;
	struct edid *edid;
	struct mutex lock;

	u8 i2c_addr;
	u8 pcr_m;
	int irq;
	bool ac_mode;
	int intf_num;

	u32 irq_gpio;
	u32 reset_gpio;
	u32 hdmi_ps_gpio;
	u32 hdmi_en_gpio;

	unsigned int num_vreg;
	struct lt9611_vreg *vreg_config;

	struct i2c_client *i2c_client;

	enum drm_connector_status status;
	bool power_on;
	bool regulator_on;

	/* get display modes from device tree */
	bool non_pluggable;
	u32 num_of_modes;
	struct list_head mode_list;
	struct list_head support_mode_list;

	struct drm_display_mode curr_mode;
	struct drm_display_mode debug_mode;
	struct lt9611_video_cfg video_cfg;

	struct workqueue_struct *wq;
	struct work_struct work;
	wait_queue_head_t edid_wq;

	u8 edid_buf[EDID_SEG_SIZE];
	u8 i2c_wbuf[WRITE_BUF_MAX_SIZE];
	u8 i2c_rbuf[READ_BUF_MAX_SIZE];
	bool hdmi_mode;
	bool edid_complete;
	bool bridge_attach;
	bool hpd_status;
	bool pending_edid;
	bool edid_status;
	bool hpd_trigger;
	bool fix_mode;

	u32 chip_ip;

	const struct lt9611_chip_funcs *lt9611_func;
};

struct lt9611_timing_info {
	u16 xres;
	u16 yres;
	u8 bpp;
	u8 fps;
	u8 lanes;
	u8 intfs;
};

struct lt9611_chip_funcs {
	void (*reset_chip)(struct lt9611 *pdata, bool on_off);
	int (*init_setup)(struct lt9611 *pdata);
	irqreturn_t (*irq_handle)(int irq, void *dev_id);
	enum drm_connector_status (*detect)(struct drm_connector *connector, bool force);
	void (*video_cfg)(struct lt9611 *pdata, struct drm_display_mode *mode,
		struct lt9611_video_cfg *video_cfg);
	int (*read_edid)(struct lt9611 *pdata);
	int (*video_update)(struct lt9611 *pdata);
	int (*video_on)(struct lt9611 *pdata, bool on);
};

static int lt9611_get_edid_block(void *data, u8 *buf, unsigned int block,
		size_t len);
static int lt9611_enable_interrupts(struct lt9611 *pdata,
		int interrupts, bool on);
static bool lt9611_hpd_status(struct lt9611 *pdata);

/*
 * Write one reg with one value;
 * Reg -> value
 */
static int lt9611_write_byte(struct lt9611 *pdata, const u8 reg, u8 value)
{
	struct i2c_client *client = pdata->i2c_client;
	struct i2c_msg msg = {
		.addr = client->addr,
		.flags = 0,
		.len = 2,
		.buf = pdata->i2c_wbuf,
	};

	memset(pdata->i2c_wbuf, 0, WRITE_BUF_MAX_SIZE);
	pdata->i2c_wbuf[0] = reg;
	pdata->i2c_wbuf[1] = value;

	if (i2c_transfer(client->adapter, &msg, 1) < 1) {
		pr_err("i2c write failed\n");
		return -EIO;
	}

	return 0;
}

/*
 * Write more regs with more values;
 * Reg1 -> value1
 * Reg2 -> value2
 */
static void lt9611_write_array(struct lt9611 *pdata,
	struct lt9611_reg_cfg *reg_arry, int size)
{
	int i = 0;

	for (i = 0; i < size; i++)
		lt9611_write_byte(pdata, reg_arry[i].reg, reg_arry[i].val);
}

static int lt9611_read(struct lt9611 *pdata, u8 reg, char *buf, u32 size)
{
	struct i2c_client *client = pdata->i2c_client;
	struct i2c_msg msg[2] = {
		{
			.addr = client->addr,
			.flags = 0,
			.len = 1,
			.buf = pdata->i2c_wbuf,
		},
		{
			.addr = client->addr,
			.flags = I2C_M_RD,
			.len = size,
			.buf = pdata->i2c_rbuf,
		}
	};

	if (size > READ_BUF_MAX_SIZE) {
		pr_err("invalid read buff size %d\n", size);
		return -EINVAL;
	}

	memset(pdata->i2c_wbuf, 0x0, WRITE_BUF_MAX_SIZE);
	memset(pdata->i2c_rbuf, 0x0, READ_BUF_MAX_SIZE);
	pdata->i2c_wbuf[0] = reg;

	if (i2c_transfer(client->adapter, msg, 2) != 2) {
		pr_err("i2c read failed\n");
		return -EIO;
	}

	memcpy(buf, pdata->i2c_rbuf, size);

	return 0;
}

static struct lt9611 *bridge_to_lt9611(struct drm_bridge *bridge)
{
	return container_of(bridge, struct lt9611, bridge);
}

static struct lt9611 *connector_to_lt9611(struct drm_connector *connector)
{
	return container_of(connector, struct lt9611, connector);
}

static enum drm_connector_status
lt9611_connector_detect_com(struct drm_connector *connector, bool force) {
	struct lt9611 *pdata = connector_to_lt9611(connector);

	if (pdata->lt9611_func->detect)
		return pdata->lt9611_func->detect(connector, force);
	else
		return connector_status_disconnected;
}

static void lt9611_hpd_work(struct work_struct *work)
{
	struct drm_device *dev = NULL;
	char name[HPD_UEVENT_BUFFER_SIZE], status[HPD_UEVENT_BUFFER_SIZE];
	char *event_string = "HOTPLUG=1";
	char *envp[5];
	enum drm_connector_status last_status;
	struct lt9611 *pdata = container_of(work, struct lt9611, work);
	struct drm_display_mode *mode, *n;

	pr_info("@lt9611 hpd_work\n");

	if (!pdata || !pdata->connector.funcs ||
		!pdata->connector.funcs->detect) {
		pr_err("not init done before hpd_work\n");
		return;
	}

	lt9611_enable_interrupts(pdata, CFG_HPD_INTERRUPTS, 1);

	dev = pdata->connector.dev;

	pdata->hpd_status = lt9611_hpd_status(pdata);
	last_status = pdata->connector.status;
	pdata->connector.status = pdata->hpd_status;

	if (last_status == pdata->connector.status) {
		pr_info("hpd same status ignore\n");
		return;
	}

	if (pdata->connector.status == connector_status_connected) {
		int ret = 0;
		int count = 0;

		/* For compatibility keep last edid until next HDMI plug on. */
		if (pdata->edid) {
			list_for_each_entry_safe(mode, n,
				&pdata->support_mode_list, head) {
				list_del(&mode->head);
				kfree(mode);
			}
			kfree(pdata->edid);
			pdata->edid = NULL;
		}

		/* EDID error handle,
		 * Multi consecutive errors means sink edid block is broken.
		 */
		do {
			ret = pdata->lt9611_func->read_edid(pdata);
			count++;
			pr_info("read edid cnt(%d)\n", count);
		} while (ret != 0 && (count < EDID_ERR_RETRY));

		pdata->edid = drm_do_get_edid(&pdata->connector,
			lt9611_get_edid_block, pdata);
	}

	scnprintf(name, HPD_UEVENT_BUFFER_SIZE, "name=%s",
		pdata->connector.name);
	scnprintf(status, HPD_UEVENT_BUFFER_SIZE, "status=%s",
		drm_get_connector_status_name(pdata->connector.status));

	pr_info("@lt9611 [%s]:[%s]\n", name, status);
	envp[0] = name;
	envp[1] = status;
	envp[2] = event_string;
	envp[3] = NULL;
	envp[4] = NULL;
	kobject_uevent_env(&dev->primary->kdev->kobj, KOBJ_CHANGE,
		envp);
}

static bool lt9611_hpd_status(struct lt9611 *pdata)
{
	u8 reg_val;

	lt9611_write_byte(pdata, 0xff, 0x82);
	lt9611_read(pdata, 0x5e, &reg_val, 1);
	if (reg_val & BIT(2))
		return 1;
	else
		return 0;
}

static void lt9611_parse_dt_modes(struct device_node *np,
		struct list_head *head,
		u32 *num_of_modes)
{
	int rc = 0;
	struct drm_display_mode *mode;
	u32 mode_count = 0;
	struct device_node *node = NULL;
	struct device_node *root_node = NULL;
	u32 h_front_porch, h_pulse_width, h_back_porch;
	u32 v_front_porch, v_pulse_width, v_back_porch;
	bool h_active_high, v_active_high;
	u32 flags = 0;

	root_node = of_get_child_by_name(np, "lt,customize-modes");
	if (!root_node) {
		root_node = of_parse_phandle(np, "lt,customize-modes", 0);
		if (!root_node) {
			pr_info("No entry present for lt,customize-modes\n");
			return;
		}
	}

	for_each_child_of_node(root_node, node) {
		rc = 0;
		mode = kzalloc(sizeof(*mode), GFP_KERNEL);
		if (!mode) {
			pr_err("Out of memory\n");
			rc =  -ENOMEM;
			continue;
		}

		rc = of_property_read_u32(node, "lt,mode-h-active",
			&mode->hdisplay);
		if (rc) {
			pr_err("failed to read h-active, rc=%d\n", rc);
			goto fail;
		}

		rc = of_property_read_u32(node, "lt,mode-h-front-porch",
			&h_front_porch);
		if (rc) {
			pr_err("failed to read h-front-porch, rc=%d\n", rc);
			goto fail;
		}

		rc = of_property_read_u32(node, "lt,mode-h-pulse-width",
			&h_pulse_width);
		if (rc) {
			pr_err("failed to read h-pulse-width, rc=%d\n", rc);
			goto fail;
		}

		rc = of_property_read_u32(node, "lt,mode-h-back-porch",
			&h_back_porch);
		if (rc) {
			pr_err("failed to read h-back-porch, rc=%d\n", rc);
			goto fail;
		}

		h_active_high = of_property_read_bool(node,
			"lt,mode-h-active-high");

		rc = of_property_read_u32(node, "lt,mode-v-active",
			&mode->vdisplay);
		if (rc) {
			pr_err("failed to read v-active, rc=%d\n", rc);
			goto fail;
		}

		rc = of_property_read_u32(node, "lt,mode-v-front-porch",
			&v_front_porch);
		if (rc) {
			pr_err("failed to read v-front-porch, rc=%d\n", rc);
			goto fail;
		}

		rc = of_property_read_u32(node, "lt,mode-v-pulse-width",
			&v_pulse_width);
		if (rc) {
			pr_err("failed to read v-pulse-width, rc=%d\n", rc);
			goto fail;
		}

		rc = of_property_read_u32(node, "lt,mode-v-back-porch",
			&v_back_porch);
		if (rc) {
			pr_err("failed to read v-back-porch, rc=%d\n", rc);
			goto fail;
		}

		v_active_high = of_property_read_bool(node,
			"lt,mode-v-active-high");

		rc = of_property_read_u32(node, "lt,mode-refresh-rate",
			&mode->vrefresh);
		if (rc) {
			pr_err("failed to read refresh-rate, rc=%d\n", rc);
			goto fail;
		}

		rc = of_property_read_u32(node, "lt,mode-clock-in-khz",
			&mode->clock);
		if (rc) {
			pr_err("failed to read clock, rc=%d\n", rc);
			goto fail;
		}

		mode->hsync_start = mode->hdisplay + h_front_porch;
		mode->hsync_end = mode->hsync_start + h_pulse_width;
		mode->htotal = mode->hsync_end + h_back_porch;
		mode->vsync_start = mode->vdisplay + v_front_porch;
		mode->vsync_end = mode->vsync_start + v_pulse_width;
		mode->vtotal = mode->vsync_end + v_back_porch;
		if (h_active_high)
			flags |= DRM_MODE_FLAG_PHSYNC;
		else
			flags |= DRM_MODE_FLAG_NHSYNC;
		if (v_active_high)
			flags |= DRM_MODE_FLAG_PVSYNC;
		else
			flags |= DRM_MODE_FLAG_NVSYNC;
		mode->flags = flags;

		if (!rc) {
			mode_count++;
			list_add_tail(&mode->head, head);
		}

		drm_mode_set_name(mode);

		pr_debug("mode[%s] h[%d,%d,%d,%d] v[%d,%d,%d,%d] %d %x %dkHZ\n",
			mode->name, mode->hdisplay, mode->hsync_start,
			mode->hsync_end, mode->htotal, mode->vdisplay,
			mode->vsync_start, mode->vsync_end, mode->vtotal,
			mode->vrefresh, mode->flags, mode->clock);
fail:
		if (rc) {
			kfree(mode);
			continue;
		}
	}

	if (num_of_modes)
		*num_of_modes = mode_count;
}

static int lt9611_gpio_configure(struct lt9611 *pdata, bool on)
{
	int ret = 0;

	if (on) {
		ret = gpio_request(pdata->reset_gpio,
			"lt9611-reset-gpio");
		if (ret) {
			pr_err("lt9611 reset gpio request failed\n");
			goto error;
		}

		ret = gpio_direction_output(pdata->reset_gpio, 0);
		if (ret) {
			pr_err("lt9611 reset gpio direction failed\n");
			goto reset_error;
		}

		if (gpio_is_valid(pdata->hdmi_en_gpio)) {
			ret = gpio_request(pdata->hdmi_en_gpio,
				"lt9611-hdmi-en-gpio");
			if (ret) {
				pr_err("lt9611 hdmi en gpio request failed\n");
				goto reset_error;
			}

			ret = gpio_direction_output(pdata->hdmi_en_gpio, 0);
			if (ret) {
				pr_err("lt9611 hdmi en gpio direction failed\n");
				goto hdmi_en_error;
			}
		}

		if (gpio_is_valid(pdata->hdmi_ps_gpio)) {
			ret = gpio_request(pdata->hdmi_ps_gpio,
				"lt9611-hdmi-ps-gpio");
			if (ret) {
				pr_err("lt9611 hdmi ps gpio request failed\n");
				goto hdmi_en_error;
			}

			ret = gpio_direction_output(pdata->hdmi_ps_gpio, 0);
			if (ret) {
				pr_err("lt9611 hdmi ps gpio direction failed\n");
				goto hdmi_ps_error;
			}
		}

		ret = gpio_request(pdata->irq_gpio, "lt9611-irq-gpio");
		if (ret) {
			pr_err("lt9611 irq gpio request failed\n");
			goto hdmi_ps_error;
		}

		ret = gpio_direction_input(pdata->irq_gpio);
		if (ret) {
			pr_err("lt9611 irq gpio direction failed\n");
			goto irq_error;
		}
	} else {
		gpio_free(pdata->irq_gpio);
		if (gpio_is_valid(pdata->hdmi_ps_gpio))
			gpio_free(pdata->hdmi_ps_gpio);
		if (gpio_is_valid(pdata->hdmi_en_gpio))
			gpio_free(pdata->hdmi_en_gpio);
		gpio_free(pdata->reset_gpio);
	}

	return ret;


irq_error:
	gpio_free(pdata->irq_gpio);
hdmi_ps_error:
	if (gpio_is_valid(pdata->hdmi_ps_gpio))
		gpio_free(pdata->hdmi_ps_gpio);
hdmi_en_error:
	if (gpio_is_valid(pdata->hdmi_en_gpio))
		gpio_free(pdata->hdmi_en_gpio);
reset_error:
	gpio_free(pdata->reset_gpio);
error:
	return ret;
}

static int lt9611_mipi_input_analog(struct lt9611 *pdata,
		struct lt9611_video_cfg *cfg)
{
	struct lt9611_reg_cfg reg_cfg[] = {
		{0xff, 0x81},
		{0x06, 0x60},	/* port A rx current */
		{0x07, 0x3f},	/* eq */
		{0x08, 0x3f},	/* eq */

		{0x0a, 0xfe},	/* port A ldo voltage set */
		{0x0b, 0xbf},	/* enable port A lprx */
		{0x11, 0x60},	/* port B rx current */
		{0x12, 0x3f},	/* eq */
		{0x13, 0x3f},	/* eq */
		{0x15, 0xfe},	/* port B ldo voltage set */
		{0x16, 0xbf},	/* enable port B lprx */

		{0x1c, 0x03},	/* PortA clk lane no-LP mode */
		{0x20, 0x03},	/* PortB clk lane with-LP mode */
	};

	if (!pdata || !cfg) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	lt9611_write_array(pdata, reg_cfg, ARRAY_SIZE(reg_cfg));

	return 0;
}

static int lt9611_mipi_input_digital(struct lt9611 *pdata,
	struct lt9611_video_cfg *cfg)
{
	u8 lanes = 0;
	u8 ports = 0;
	struct lt9611_reg_cfg reg_cfg[] = {
		{0xff, 0x82},
		{0x4f, 0x80},
		{0x50, 0x14},	/* signal port switch portA:0x10 portB:0x14 */
		{0xff, 0x83},
		{0x03, 0x40},	/* signal port switch portA:0x00 portB:0x40 */
		{0x02, 0x08},
		{0x06, 0x08},
	};

	if (!pdata || !cfg) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	lanes = 4;
	ports = pdata->intf_num;

	lt9611_write_byte(pdata, 0xff, 0x83);
	if (lanes == 4)
		lt9611_write_byte(pdata, 0x00, 0x00);
	else if (lanes < 4)
		lt9611_write_byte(pdata, 0x00, lanes);
	else {
		pr_err("invalid lane count\n");
		return -EINVAL;
	}

	if (ports == 1)
		lt9611_write_byte(pdata, 0x0a, 0x00);
	else if (ports == 2)
		lt9611_write_byte(pdata, 0x0a, 0x03);
	else {
		pr_err("invalid port count\n");
		return -EINVAL;
	}

	lt9611_write_array(pdata, reg_cfg, ARRAY_SIZE(reg_cfg));

	return 0;
}

static struct lt9611_vid_cfg *lt9611_mipi_video_get(struct lt9611_video_cfg *cfg)
{
	struct lt9611_vid_cfg *vid_cfg;

	vid_cfg = kzalloc(sizeof(*vid_cfg), GFP_KERNEL);
	vid_cfg->h_total = cfg->h_active +
		cfg->h_front_porch + cfg->h_pulse_width
		+ cfg->h_back_porch;
	vid_cfg->v_total = cfg->v_active + cfg->v_front_porch +
		cfg->v_pulse_width + cfg->v_back_porch;

	vid_cfg->h_act = cfg->h_active;
	vid_cfg->hpw = cfg->h_pulse_width;
	vid_cfg->hfp = cfg->h_front_porch;
	vid_cfg->hss = cfg->h_pulse_width + cfg->h_back_porch;

	vid_cfg->v_act = cfg->v_active;
	vid_cfg->vpw = cfg->v_pulse_width;
	vid_cfg->vfp = cfg->v_front_porch;
	vid_cfg->vss = cfg->v_pulse_width + cfg->v_back_porch;

	pr_debug("@lt9611 get h_total=%d, h_active=%d, hfp=%d, hpw=%d, hbp=%d\n",
		vid_cfg->h_total, cfg->h_active, cfg->h_front_porch,
		cfg->h_pulse_width, cfg->h_back_porch);

	pr_debug("@lt9611 get v_total=%d, v_active=%d, vfp=%d, vpw=%d, vbp=%d\n",
		vid_cfg->v_total, cfg->v_active, cfg->v_front_porch,
		cfg->v_pulse_width, cfg->v_back_porch);

	return vid_cfg;
}

static void lt9611_mipi_video_setup(struct lt9611 *pdata,
	struct lt9611_video_cfg *cfg)
{
	struct lt9611_vid_cfg *vid_cfg = lt9611_mipi_video_get(cfg);
	struct lt9611_reg_cfg reg_cfg[] = {
		{0xff, 0x83},
		{0x0d, (u8)(vid_cfg->v_total / 256)},
		{0x0e, (u8)(vid_cfg->v_total % 256)},
		{0x0f, (u8)(vid_cfg->v_act / 256)},
		{0x10, (u8)(vid_cfg->v_act % 256)},
		{0x11, (u8)(vid_cfg->h_total / 256)},
		{0x12, (u8)(vid_cfg->h_total % 256)},
		{0x13, (u8)(vid_cfg->h_act / 256)},
		{0x14, (u8)(vid_cfg->h_act % 256)},
		{0x15, (u8)(vid_cfg->vpw % 256)},
		{0x16, (u8)(vid_cfg->hpw % 256)},
		{0x17, (u8)(vid_cfg->vfp % 256)},
		{0x18, (u8)(vid_cfg->vss % 256)},
		{0x19, (u8)(vid_cfg->hfp % 256)},
		{0x1a, (u8)(vid_cfg->hss / 256)},
		{0x1b, (u8)(vid_cfg->hss % 256)},
	};

	if (!pdata || !cfg) {
		pr_err("invalid input\n");
		return;
	}

	pr_debug("@lt9611 setup HxV=%dx%d pclk=%d\n",
		cfg->h_active, cfg->v_active, cfg->pclk_khz);

	lt9611_write_array(pdata, reg_cfg, ARRAY_SIZE(reg_cfg));
}

static int lt9611_pcr_setup(struct lt9611 *pdata,
		struct lt9611_video_cfg *cfg)
{
	u32 h_act = 0;
	u32 v_act = 0;

	struct lt9611_reg_cfg reg_cfg[] = {
		{0xff, 0x83},
		{0x0b, 0x01},	/* vsync mode */
		{0x0c, 0x10},	/* =1/4 hact */
		{0x48, 0x00},	/* de mode delay */
		{0x49, 0x81},

		/* stage 1 */
		{0x21, 0x4a},
		{0x24, 0x71},	/* bit[7:4]v/h/de mode; line for clk stb[11:8] */
		{0x25, 0x30},	/* line for clk stb[7:0] */
		{0x2a, 0x01},	/* clk stable in */

		/* stage 2 */
		{0x4a, 0x40},	/* offset */
		{0x1d, 0x10},	/* PCR de mode step setting */
	};

	struct lt9611_reg_cfg reg_cfg_480p[] = {
		{0xff, 0x83},
		{0x0b, 0x02},
		{0x0c, 0x40},
		{0x48, 0x01},
		{0x49, 0x10},
		{0x24, 0x70},
		{0x25, 0x80},
		{0x2a, 0x10},
		{0x2b, 0x80},
		{0x23, 0x28},	/* pcr h mode step */
		{0x4a, 0x10},	/* offset */
		{0x1d, 0xf3},
	};

	struct lt9611_reg_cfg reg_cfg_vesa_spe[] = {
		{0x24, 0x70},	/* bit[7:4]v/h/de mode; line for clk stb[11:8] */
		{0x25, 0x80},	/* line for clk stb[7:0] */
		{0x2a, 0x10},	/* clk stable in */
		{0x1d, 0xf0},	/* PCR de mode step setting */

	};


	struct lt9611_reg_cfg pcr_rst[] = {
		{0xff, 0x80},
		{0x11, 0x5a},
		{0x11, 0xfa},
	};

	if (!pdata || !cfg) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	lt9611_write_array(pdata, reg_cfg, ARRAY_SIZE(reg_cfg));

	h_act = cfg->h_active;
	v_act = cfg->v_active;

	if (((h_act == 720) || (h_act == 640)) && (v_act == 480)) {
		pr_debug("lt9611_pcr_setup: 640x480_60Hz\n");
		lt9611_write_array(pdata, reg_cfg_480p, ARRAY_SIZE(reg_cfg_480p));
	} else if (((h_act == 540) && (v_act == 960)) ||
		((h_act == 1024) && (v_act == 600))) {
		pr_debug("lt9611_pcr_setup: Special vesa\n");
		lt9611_write_array(pdata, reg_cfg_vesa_spe, ARRAY_SIZE(reg_cfg_vesa_spe));
	}

	lt9611_mipi_video_setup(pdata, cfg);

	lt9611_write_byte(pdata, 0xff, 0x83);
	lt9611_write_byte(pdata, 0x26, pdata->pcr_m);
	/* pcr rst */
	lt9611_write_array(pdata, pcr_rst, ARRAY_SIZE(pcr_rst));

	return 0;
}

static int lt9611_pll_setup(struct lt9611 *pdata,
		struct lt9611_video_cfg *cfg)
{
	u32 pclk = 0;
	u8 hdmi_post_div;
	u8 pll_lock_flag, cal_done_flag, band_out;
	u8 i;

	struct lt9611_reg_cfg reg_cfg_pre[] = {
		/* txpll init */
		{0xff, 0x81},
		{0x23, 0x40},	/* Enable LDO and disable PD */
		{0x24, 0x62},	/* 0x62, LG25UM58 issue, 20180824 */
		{0x25, 0x80},	/* pre-divider */
		{0x26, 0x55},
		{0x2c, 0x37},
		{0x2f, 0x01},
		{0x26, 0x55},
		{0x27, 0x66},
		{0x28, 0x88},
		{0x2a, 0x20},	/* for U3 */
	};

	struct lt9611_reg_cfg reg_cfg_post[] = {
		/* txpll init */
		{0xde, 0x20},	/* pll cal en, start calibration*/
		{0xde, 0xe0},

		{0xff, 0x80},
		{0x11, 0x5a},	/* Pcr clk reset */
		{0x11, 0xfa},
		{0x16, 0xf2},	/* pll cal digital reset */
		{0x18, 0xdc},	/* pll analog reset */
		{0x18, 0xfc},
		{0x16, 0xf3},	/* start calibration */
	};

	struct lt9611_reg_cfg reg_cfg_plock[] = {
		{0xff, 0x80},
		{0x16, 0xe3},
		{0x16, 0xf3},
		{0xff, 0x82},
	};

	struct lt9611_reg_cfg reg_cfg_pll_rst[] = {
		{0xff, 0x80},
		{0x11, 0x5a},
		{0x11, 0xfa},	/* Pcr clk reset */
		{0x16, 0xf2},	/* pll cal digital reset */
		{0x18, 0xdc},	/* pll analog reset */
		{0x18, 0xfc},
		{0x16, 0xf3},	/* start calibration */
	};

	if (!pdata || !cfg) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	pclk = cfg->pclk_khz;

	pr_debug("@lt9611 set rx pll = %d", pclk);

	lt9611_write_array(pdata, reg_cfg_pre, ARRAY_SIZE(reg_cfg_pre));

	if (pclk > 150000) {
		lt9611_write_byte(pdata, 0x2d, 0x88);
		hdmi_post_div = 0x1;
	} else if (pclk > 80000) {
		lt9611_write_byte(pdata, 0x2d, 0x99);
		hdmi_post_div = 0x2;
	} else {
		lt9611_write_byte(pdata, 0x2d, 0xaa);
		hdmi_post_div = 0x4;
	}

	pdata->pcr_m = (u8)((pclk * 5 * hdmi_post_div) / 27000);
	pdata->pcr_m--;

	pr_debug("@lt9611 pcr_m = 0x%x, hdmi_post_div = %d", pdata->pcr_m, hdmi_post_div);

	lt9611_write_byte(pdata, 0xff, 0x83);
	lt9611_write_byte(pdata, 0x2d, 0x40);	/* M up limit */
	lt9611_write_byte(pdata, 0x31, 0x08);	/* M down limit */
	lt9611_write_byte(pdata, 0x26, 0x80 | pdata->pcr_m);	/* fixed M is to let pll locked */

	lt9611_write_byte(pdata, 0xff, 0x82);
	pclk = pclk / 2;
	lt9611_write_byte(pdata, 0xe3, pclk / 65536);	/* pclk[19:16] */
	pclk = pclk % 65536;
	lt9611_write_byte(pdata, 0xe4, pclk / 256);	/* pclk[15:8]  */
	lt9611_write_byte(pdata, 0xe5, pclk % 256);	/* pclk[7:0]   */

	lt9611_write_array(pdata, reg_cfg_post, ARRAY_SIZE(reg_cfg_post));

	/* pll lock status */
	for (i = 0; i < 6 ; i++) {
		lt9611_write_array(pdata, reg_cfg_plock, ARRAY_SIZE(reg_cfg_plock));

		lt9611_read(pdata, 0xe7, &cal_done_flag, 1);
		lt9611_read(pdata, 0xe6, &band_out, 1);
		lt9611_read(pdata, 0x15, &pll_lock_flag, 1);

		if ((pll_lock_flag & 0x80) && (cal_done_flag & 0x80) &&
			(band_out != 0xff)) {
			pr_debug("LT9611_PLL: HDMI pll lockedband out: 0x%x\n", band_out);
			break;
		} else {
			lt9611_write_array(pdata, reg_cfg_pll_rst,
				ARRAY_SIZE(reg_cfg_pll_rst));
			pr_err("LT9611_PLL: HDMI pll unlocked, reset pll\n");
		}
	}

	return 0;
}


static int lt9611_hdmi_tx_digital(struct lt9611 *pdata,
		struct lt9611_video_cfg *cfg)
{
	int ret = -EINVAL;
	u32 checksum, vic;
	struct lt9611_reg_cfg reg_cfg[] = {
		{0xff, 0x82},
		{0xd6, 0x8e},
		{0xd7, 0x04},

		{0xff, 0x84},
		{0x10, 0x02}, /* data iland */
		{0x12, 0x64}, /* act_h_blank */
	};

	struct lt9611_reg_cfg reg_cfg_4k30[] = {
		{0xff, 0x84},
		{0x3d, 0x28}, /* AVI 0x08 | UD0 0x20 */

		{0x74, 0x81}, /* HB0 */
		{0x75, 0x01}, /* HB1 */
		{0x76, 0x05}, /* HB2 */
		{0x77, 0x49}, /* PB0 */
		{0x78, 0x03}, /* PB1 */
		{0x79, 0x0c}, /* PB2 */
		{0x7a, 0x00}, /* PB3 */
		{0x7b, 0x20}, /* PB4 */
		{0x7c, 0x01}, /* PB5 */
	};

	struct lt9611_reg_cfg reg_cfg_other[] = {
		{0xff, 0x84},
		{0x3d, 0x08}, /* AVI 0x08 */
	};

	if (!pdata || !cfg) {
		pr_err("invalid input\n");
		return ret;
	}

	vic = cfg->vic;
	checksum = 0x46 - vic;

	lt9611_write_byte(pdata, 0xff, 0x84);
	lt9611_write_byte(pdata, 0x43, checksum);
	lt9611_write_byte(pdata, 0x47, vic);

	lt9611_write_array(pdata, reg_cfg, ARRAY_SIZE(reg_cfg));

	if (vic == VIC_FIX_4k30)
		lt9611_write_array(pdata, reg_cfg_4k30, ARRAY_SIZE(reg_cfg_4k30));
	else
		lt9611_write_array(pdata, reg_cfg_other, ARRAY_SIZE(reg_cfg_other));

	return ret;
}

static int lt9611_hdmi_tx_phy(struct lt9611 *pdata,
		struct lt9611_video_cfg *cfg)
{
	int ret = -EINVAL;
	struct lt9611_reg_cfg reg_cfg[] = {
		{0xff, 0x81},
		{0x30, 0x6a},
		{0x31, 0x44},	/* HDMI DC mode */
		{0x32, 0x4a},
		{0x33, 0x0b},
		{0x34, 0x00},
		{0x35, 0x00},
		{0x36, 0x00},
		{0x37, 0x44},
		{0x3f, 0x0f},
		{0x40, 0x98},	/* clk swing */
		{0x41, 0x98},	/* D0 swing */
		{0x42, 0x98},	/* D1 swing */
		{0x43, 0x98},	/* D2 swing */
		{0x44, 0x0a},
	};

	if (!pdata || !cfg) {
		pr_err("invalid input\n");
		return ret;
	}

	/* HDMI AC mode */
	if (pdata->ac_mode)
		reg_cfg[2].val = 0x73;

	lt9611_write_array(pdata, reg_cfg, ARRAY_SIZE(reg_cfg));

	return ret;
}

static void lt9611_hdmi_output_enable(struct lt9611 *pdata)
{
	struct lt9611_reg_cfg reg_cfg[] = {
		{0xff, 0x81},
		{0x23, 0x40},

		{0xff, 0x82},
		{0xde, 0x20},
		{0xde, 0xe0},

		{0xff, 0x80},
		{0x18, 0xdc},	/* txpll sw rst */
		{0x18, 0xfc},
		{0x16, 0xf1},	/* txpll calibration rest */
		{0x16, 0xf3},

		{0x11, 0x5a},	/* Pcr reset */
		{0x11, 0xfa},

		{0xff, 0x81},
		{0x30, 0xea},
	};

	if (!pdata) {
		pr_err("lt9611 en invalid input\n");
		return;
	}

	lt9611_write_array(pdata, reg_cfg, sizeof(reg_cfg));
}

static void lt9611_hdmi_output_disable(struct lt9611 *pdata)
{
	lt9611_write_byte(pdata, 0xff, 0x81);
	lt9611_write_byte(pdata, 0x30, 0x00);	/* Txphy PD */
	lt9611_write_byte(pdata, 0x23, 0x80);	/* Txpll PD */
}

static void lt9611_lowpower_mode(struct lt9611 *pdata, bool on) 
{
	struct lt9611_reg_cfg lp_on[] = {
		{0xff, 0x81},
		{0x02, 0x49},
		{0x23, 0x80},
		{0x30, 0x00},
		{0xff, 0x80},
		{0x11, 0x0a},
	};

	struct lt9611_reg_cfg lp_off[] = {
		{0xff, 0x81},
		{0x02, 0x12},
		{0x23, 0x40},
		{0x30, 0xea},
		{0xff, 0x80},
		{0x11, 0xfa},
	};

	if (on)
		lt9611_write_array(pdata, lp_on, ARRAY_SIZE(lp_on));
	else
		lt9611_write_array(pdata, lp_off, ARRAY_SIZE(lp_off));
}

static void lt9611_init_interrupts(struct lt9611 *pdata)
{
	/* Init interrupt
	 * HPD debounce is used for HPD stable time,
	 * with default debounce 0x80, HDMI switch can not detect,
	 * after redude to 0x40 can detect switch HPD change.
	 */
	struct lt9611_reg_cfg isr_init[] = {
		{0xff, 0x82},
		{0x58, 0x0a},	/* Det HPD 0x08 --> 0x0a */
		{0x59, 0x40},	/* HPD debounce width */
		{0x9e, 0xf7},	/* initial vid change interrupt */
	};

	if (!pdata) {
		pr_err("@lt9611 invalid input\n");
		return;
	}

	lt9611_write_array(pdata, isr_init, ARRAY_SIZE(isr_init));
}

static int lt9611_enable_interrupts(struct lt9611 *pdata, int interrupts, bool on)
{
	int ret = 0;

	struct lt9611_reg_cfg hpd_on[] = {
		{0xff, 0x82},
		{0x07, 0xff},
		{0x07, 0x3f},
		{0x03, 0x3f},
	};

	struct lt9611_reg_cfg hpd_off[] = {
		{0xff, 0x82},
		{0x07, 0xff},
		{0x03, 0xff},
	};

	struct lt9611_reg_cfg vid_on[] = {
		{0xff, 0x82},
		{0x9e, 0xff},
		{0x9e, 0xf7},
		{0x04, 0xff},
		{0x04, 0xfe},
		{0x00, 0xfe},
	};

	struct lt9611_reg_cfg vid_off[] = {
		{0xff, 0x82},
		{0x04, 0xff},
		{0x00, 0xff},
	};

	if (!pdata) {
		pr_err("@lt9611 invalid input\n");
		goto end;
	}

	pr_info("@lt9611 interrupts(%x) on(%d)\n", interrupts, on);

	if (interrupts & CFG_HPD_INTERRUPTS) {
		if (on) {
			lt9611_write_array(pdata, hpd_on, ARRAY_SIZE(hpd_on));
			pr_debug("@lt9611 enable hpd irq\n");
		} else {
			lt9611_write_array(pdata, hpd_off, ARRAY_SIZE(hpd_off));
			pr_debug("@lt9611 disable hpd irq\n");
		}
	}

	if (interrupts & CFG_VID_CHK_INTERRUPTS) {
		if (on) {
			lt9611_write_array(pdata, vid_on, ARRAY_SIZE(vid_on));
			pr_debug("@lt9611 vid chg irq enable\n");
		} else {
			lt9611_write_array(pdata, vid_off, ARRAY_SIZE(vid_off));
			pr_debug("@lt9611 vid chg irq disable\n");
		}
	}

end:
	return ret;
}

static irqreturn_t lt9611_irq_thread_handler(int irq, void *dev_id)
{
	struct lt9611 *pdata = dev_id;
	u8 irq_flag3 = 0;
	u8 irq_flag0 = 0;

	struct lt9611_reg_cfg clr_irq3[] = {
		{0xff, 0x82},	/* irq 3 clear flag */
		{0x07, 0xff},
		{0x07, 0x3f},
	};

	struct lt9611_reg_cfg clr_irq0[] = {
		{0xff, 0x82},	/* irq 0 clear flag */
		{0x9e, 0xff},
		{0x9e, 0xf7},
		{0x04, 0xff},
		{0x04, 0xfe},
	};

	if (!pdata->power_on)
	{
		pr_err("@lt9611 irq with power off\n");
		return IRQ_HANDLED;
	}

	lt9611_write_byte(pdata, 0xff, 0x82);
	lt9611_read(pdata, 0x0f, &irq_flag3, 1);
	lt9611_read(pdata, 0x0c, &irq_flag0, 1);

	pr_info("@lt9611 hpd_irq(%x) vid(%x)\n", irq_flag3, irq_flag0);

	/* hpd changed */
	if (irq_flag3 & (BIT(6) | BIT(7))) {
		/* For lt9611 HPD interrupt control,
		 * interrupt happended during clr interrupt bit and return ISR,
		 * then no interrupt can be detected after this.
		 * So need disable HPD interrupt before clr interrupt,
		 * and enable HPD interrupt in queue work.
		 */
		lt9611_enable_interrupts(pdata, CFG_HPD_INTERRUPTS, 0);

		lt9611_write_array(pdata, clr_irq3, ARRAY_SIZE(clr_irq3));
		queue_work(pdata->wq, &pdata->work);
	}

	/* vid changed */
	if (irq_flag0 & (BIT(0)))
		lt9611_write_array(pdata, clr_irq0, ARRAY_SIZE(clr_irq0));

	return IRQ_HANDLED;
}

static int lt9611_system_init(struct lt9611 *pdata)
{
	struct lt9611_reg_cfg init_setup[] = {
		{0xFF, 0x82},
		{0x51, 0x11},

		/* timer for frequency meter */
		{0xff, 0x82},
		{0x1b, 0x69},	/*timer 2*/
		{0x1c, 0x78},
		{0xcb, 0x69},	/*timer 1 */
		{0xcc, 0x78},

		/* power consumption for work */
		{0xff, 0x80},
		{0x04, 0xf0},
		{0x06, 0xf0},
		{0x0a, 0x80},
		{0x0b, 0x46},	//csc clk | old {0x0b, 0x40},
		{0x0d, 0xef},
		{0x11, 0xfa},
	};

	if (!pdata) {
		pr_err("@lt9611 invalid input\n");
		return -1;
	}

	lt9611_write_array(pdata, init_setup,
		ARRAY_SIZE(init_setup));

	return 0;
}

static int lt9611_read_chip_id(struct lt9611 *pdata)
{
	int ret = 0;
	u8 id0, id1, id2;
	struct lt9611_reg_cfg ctl_en[] = {
		{0xFF, 0x80},
		{0xee, 0x01},	/* port A rx current */
	};

	struct lt9611_reg_cfg xtal_clk[] = {
		{0xFF, 0x81},
		{0x01, 0x18},	/* port A rx current */
		{0xFF, 0x80},
	};

	if (!pdata) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	lt9611_write_array(pdata, ctl_en, ARRAY_SIZE(ctl_en));

	pdata->chip_ip = 0;

	lt9611_read(pdata, 0x00, &id0, 1);
	lt9611_read(pdata, 0x01, &id1, 1);
	lt9611_read(pdata, 0x02, &id2, 1);

	pdata->chip_ip = ((id0 & 0xff) << 16) | ((id1 & 0xff) << 8) | (id2 & 0xff);

	pr_debug("@lt9611 ring Chip ID = 0x%08x\n", pdata->chip_ip);

	lt9611_write_array(pdata, xtal_clk, ARRAY_SIZE(xtal_clk));

	return ret;
}

static int lt9611_init_setup(struct lt9611 *pdata)
{
	int ret = 0;

	struct lt9611_video_cfg *cfg = &pdata->video_cfg;

	if (!pdata || !cfg) {
		pr_err("@lt9611 invalid input\n");
		return -1;
	}

	pr_info("@lt9611_init setup\n");
	lt9611_read_chip_id(pdata);
	lt9611_system_init(pdata);
	lt9611_mipi_input_analog(pdata, cfg);
	lt9611_mipi_input_digital(pdata, cfg);
	lt9611_hdmi_tx_phy(pdata, cfg);

	/* init hdmi hpd intr */
	lt9611_lowpower_mode(pdata, 0);
	lt9611_init_interrupts(pdata);
	lt9611_enable_interrupts(pdata, CFG_HPD_INTERRUPTS, 1);

	queue_work(pdata->wq, &pdata->work);

	return ret;
}

static int lt9611_power_on(struct lt9611 *pdata, bool on_off)
{
	if (!gpio_is_valid(pdata->hdmi_ps_gpio) ||
		!gpio_is_valid(pdata->hdmi_en_gpio) ||
		!gpio_is_valid(pdata->reset_gpio))
	{
		pr_err("@lt9611 gpio err Pw on\n");
		return -1;
	}

	pr_info("@lt9611 power (%d)\n", on_off);
	pdata->power_on = on_off;

	if (on_off) {
		gpio_set_value(pdata->hdmi_ps_gpio, 1);
		msleep(20);
		gpio_set_value(pdata->hdmi_en_gpio, 1);
		msleep(50);
		gpio_set_value(pdata->reset_gpio, 1);
		msleep(50);
	} else {
		gpio_set_value(pdata->reset_gpio, 0);
		msleep(10);
		gpio_set_value(pdata->hdmi_en_gpio, 0);
		msleep(10);
		gpio_set_value(pdata->hdmi_ps_gpio, 0);
		msleep(50);
	}

	return 0;
}

static int lt9611_video_update(struct lt9611 *pdata)
{
	struct lt9611_video_cfg *cfg;

	pr_debug("@lt9611 video update\n");

	if (!pdata) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	cfg = &pdata->video_cfg;
	lt9611_pll_setup(pdata, cfg);
	lt9611_pcr_setup(pdata, cfg);

	//info frame
	lt9611_hdmi_tx_digital(pdata, cfg);

	return 0;
}

static int lt9611_video_on(struct lt9611 *pdata, bool on)
{
	int ret = 0;

	pr_debug("@lt9611 HDMI out(%d)", on);
	if (on) {
		lt9611_hdmi_output_enable(pdata);
	} else
		lt9611_hdmi_output_disable(pdata);

	return ret;
}

static void lt9611_reset(struct lt9611 *pdata, bool on_off)
{
	if (on_off) {
		gpio_set_value(pdata->reset_gpio, 1);
		msleep(20);
		gpio_set_value(pdata->reset_gpio, 0);
		msleep(20);
		gpio_set_value(pdata->reset_gpio, 1);
		msleep(100);
	} else
		gpio_set_value(pdata->reset_gpio, 0);
}

static int lt9611_config_vreg(struct device *dev,
	struct lt9611_vreg *in_vreg, int num_vreg, bool config)
{
	int i = 0, rc = 0;
	struct lt9611_vreg *curr_vreg = NULL;

	if (!in_vreg || !num_vreg)
		return rc;

	if (config) {
		for (i = 0; i < num_vreg; i++) {
			curr_vreg = &in_vreg[i];
			curr_vreg->vreg = regulator_get(dev,
					curr_vreg->vreg_name);
			rc = PTR_RET(curr_vreg->vreg);
			if (rc) {
				pr_err("%s get failed. rc=%d\n",
						curr_vreg->vreg_name, rc);
				curr_vreg->vreg = NULL;
				goto vreg_get_fail;
			}

			rc = regulator_set_voltage(
					curr_vreg->vreg,
					curr_vreg->min_voltage,
					curr_vreg->max_voltage);
			if (rc < 0) {
				pr_err("%s set vltg fail\n",
						curr_vreg->vreg_name);
				goto vreg_set_voltage_fail;
			}
		}
	} else {
		for (i = num_vreg-1; i >= 0; i--) {
			curr_vreg = &in_vreg[i];
			if (curr_vreg->vreg) {
				regulator_set_voltage(curr_vreg->vreg,
						0, curr_vreg->max_voltage);

				regulator_put(curr_vreg->vreg);
				curr_vreg->vreg = NULL;
			}
		}
	}
	return 0;

vreg_unconfig:
	regulator_set_load(curr_vreg->vreg, 0);

vreg_set_voltage_fail:
	regulator_put(curr_vreg->vreg);
	curr_vreg->vreg = NULL;

vreg_get_fail:
	for (i--; i >= 0; i--) {
		curr_vreg = &in_vreg[i];
		goto vreg_unconfig;
	}
	return rc;
}

static int lt9611_get_dt_supply(struct device *dev,
		struct lt9611 *pdata)
{
	int i = 0, rc = 0;
	u32 tmp = 0;
	struct device_node *of_node = NULL, *supply_root_node = NULL;
	struct device_node *supply_node = NULL;

	if (!dev || !pdata) {
		pr_err("invalid input param dev:%pK pdata:%pK\n", dev, pdata);
		return -EINVAL;
	}

	of_node = dev->of_node;

	pdata->num_vreg = 0;
	supply_root_node = of_get_child_by_name(of_node,
		"lt,supply-entries");
	if (!supply_root_node) {
		pr_info("no supply entry present\n");
		return 0;
	}

	pdata->num_vreg = of_get_available_child_count(supply_root_node);
	if (pdata->num_vreg == 0) {
		pr_info("no vreg present\n");
		return 0;
	}

	pr_debug("vreg found. count=%d\n", pdata->num_vreg);
	pdata->vreg_config = devm_kzalloc(dev, sizeof(struct lt9611_vreg) *
		pdata->num_vreg, GFP_KERNEL);
	if (!pdata->vreg_config)
		return -ENOMEM;

	for_each_available_child_of_node(supply_root_node, supply_node) {
		const char *st = NULL;

		rc = of_property_read_string(supply_node,
			"lt,supply-name", &st);
		if (rc) {
			pr_err("error reading name. rc=%d\n", rc);
			goto error;
		}

		strlcpy(pdata->vreg_config[i].vreg_name, st,
			sizeof(pdata->vreg_config[i].vreg_name));

		rc = of_property_read_u32(supply_node,
			"lt,supply-min-voltage", &tmp);
		if (rc) {
			pr_err("error reading min volt. rc=%d\n", rc);
			goto error;
		}
		pdata->vreg_config[i].min_voltage = tmp;

		rc = of_property_read_u32(supply_node,
			"lt,supply-max-voltage", &tmp);
		if (rc) {
			pr_err("error reading max volt. rc=%d\n", rc);
			goto error;
		}
		pdata->vreg_config[i].max_voltage = tmp;

		rc = of_property_read_u32(supply_node,
			"lt,supply-enable-load", &tmp);
		if (rc)
			pr_debug("no supply enable load value. rc=%d\n", rc);

		pdata->vreg_config[i].enable_load = (!rc ? tmp : 0);

		rc = of_property_read_u32(supply_node,
			"lt,supply-disable-load", &tmp);
		if (rc)
			pr_debug("no supply disable load value. rc=%d\n", rc);

		pdata->vreg_config[i].disable_load = (!rc ? tmp : 0);

		rc = of_property_read_u32(supply_node,
			"lt,supply-pre-on-sleep", &tmp);
		if (rc)
			pr_debug("no supply pre on sleep value. rc=%d\n", rc);

		pdata->vreg_config[i].pre_on_sleep = (!rc ? tmp : 0);

		rc = of_property_read_u32(supply_node,
			"lt,supply-pre-off-sleep", &tmp);
		if (rc)
			pr_debug("no supply pre off sleep value. rc=%d\n", rc);

		pdata->vreg_config[i].pre_off_sleep = (!rc ? tmp : 0);

		rc = of_property_read_u32(supply_node,
			"lt,supply-post-on-sleep", &tmp);
		if (rc)
			pr_debug("no supply post on sleep value. rc=%d\n", rc);

		pdata->vreg_config[i].post_on_sleep = (!rc ? tmp : 0);

		rc = of_property_read_u32(supply_node,
			"lt,supply-post-off-sleep", &tmp);
		if (rc)
			pr_debug("no supply post off sleep value. rc=%d\n", rc);

		pdata->vreg_config[i].post_off_sleep = (!rc ? tmp : 0);

		pr_debug("%s min=%d, max=%d, enable=%d, disable=%d,preonsleep=%d, postonsleep=%d, preoffsleep=%d,"
			"postoffsleep=%d\n",
			pdata->vreg_config[i].vreg_name,
			pdata->vreg_config[i].min_voltage,
			pdata->vreg_config[i].max_voltage,
			pdata->vreg_config[i].enable_load,
			pdata->vreg_config[i].disable_load,
			pdata->vreg_config[i].pre_on_sleep,
			pdata->vreg_config[i].post_on_sleep,
			pdata->vreg_config[i].pre_off_sleep,
			pdata->vreg_config[i].post_off_sleep);
		++i;

		rc = 0;
	}

	rc = lt9611_config_vreg(dev,
		pdata->vreg_config, pdata->num_vreg, true);
	if (rc)
		goto error;

	return rc;

error:
	if (pdata->vreg_config) {
		devm_kfree(dev, pdata->vreg_config);
		pdata->vreg_config = NULL;
		pdata->num_vreg = 0;
	}

	return rc;
}

static void lt9611_put_dt_supply(struct device *dev,
		struct lt9611 *pdata)
{
	if (!dev || !pdata) {
		pr_err("invalid input param dev:%pK pdata:%pK\n", dev, pdata);
		return;
	}

	lt9611_config_vreg(dev,
		pdata->vreg_config, pdata->num_vreg, false);

	if (pdata->vreg_config) {
		devm_kfree(dev, pdata->vreg_config);
		pdata->vreg_config = NULL;
	}
	pdata->num_vreg = 0;
}

static int lt9611_enable_vreg(struct lt9611 *pdata, int enable)
{
	int i = 0, rc = 0;
	bool need_sleep;
	struct lt9611_vreg *in_vreg = pdata->vreg_config;
	int num_vreg = pdata->num_vreg;

	if (enable) {
		for (i = 0; i < num_vreg; i++) {
			rc = PTR_RET(in_vreg[i].vreg);
			if (rc) {
				pr_err("%s regulator error. rc=%d\n",
					in_vreg[i].vreg_name, rc);
				goto vreg_set_opt_mode_fail;
			}

			need_sleep = !regulator_is_enabled(in_vreg[i].vreg);
			if (in_vreg[i].pre_on_sleep && need_sleep)
				usleep_range(in_vreg[i].pre_on_sleep * 1000,
					in_vreg[i].pre_on_sleep * 1000);

			rc = regulator_set_load(in_vreg[i].vreg,
					in_vreg[i].enable_load);
			if (rc < 0) {
				pr_err("%s set opt m fail\n",
					in_vreg[i].vreg_name);
				goto vreg_set_opt_mode_fail;
			}

			rc = regulator_enable(in_vreg[i].vreg);
			if (in_vreg[i].post_on_sleep && need_sleep)
				usleep_range(in_vreg[i].post_on_sleep * 1000,
					in_vreg[i].post_on_sleep * 1000);
			if (rc < 0) {
				pr_err("%s enable failed\n",
					in_vreg[i].vreg_name);
				goto disable_vreg;
			}
		}
	} else {
		for (i = num_vreg-1; i >= 0; i--) {
			if (in_vreg[i].pre_off_sleep)
				usleep_range(in_vreg[i].pre_off_sleep * 1000,
					in_vreg[i].pre_off_sleep * 1000);

			regulator_set_load(in_vreg[i].vreg,
				in_vreg[i].disable_load);
			regulator_disable(in_vreg[i].vreg);

			if (in_vreg[i].post_off_sleep)
				usleep_range(in_vreg[i].post_off_sleep * 1000,
					in_vreg[i].post_off_sleep * 1000);
		}
	}
	return rc;

disable_vreg:
	regulator_set_load(in_vreg[i].vreg, in_vreg[i].disable_load);

vreg_set_opt_mode_fail:
	for (i--; i >= 0; i--) {
		if (in_vreg[i].pre_off_sleep)
			usleep_range(in_vreg[i].pre_off_sleep * 1000,
				in_vreg[i].pre_off_sleep * 1000);

		regulator_set_load(in_vreg[i].vreg,
			in_vreg[i].disable_load);
		regulator_disable(in_vreg[i].vreg);

		if (in_vreg[i].post_off_sleep)
			usleep_range(in_vreg[i].post_off_sleep * 1000,
				in_vreg[i].post_off_sleep * 1000);
	}

	return rc;
}

static void lt9611_set_video_cfg(struct lt9611 *pdata,
	struct drm_display_mode *mode,
	struct lt9611_video_cfg *video_cfg)
{
	int rc = 0;
	struct hdmi_avi_infoframe avi_frame;

	memset(&avi_frame, 0, sizeof(avi_frame));

	video_cfg->h_active = mode->hdisplay;
	video_cfg->v_active = mode->vdisplay;
	video_cfg->h_front_porch = mode->hsync_start - mode->hdisplay;
	video_cfg->v_front_porch = mode->vsync_start - mode->vdisplay;
	video_cfg->h_back_porch = mode->htotal - mode->hsync_end;
	video_cfg->v_back_porch = mode->vtotal - mode->vsync_end;
	video_cfg->h_pulse_width = mode->hsync_end - mode->hsync_start;
	video_cfg->v_pulse_width = mode->vsync_end - mode->vsync_start;
	video_cfg->pclk_khz = mode->clock;

	video_cfg->h_polarity = !!(mode->flags & DRM_MODE_FLAG_PHSYNC);
	video_cfg->v_polarity = !!(mode->flags & DRM_MODE_FLAG_PVSYNC);

	video_cfg->num_of_lanes = 4;
	video_cfg->num_of_intfs = pdata->intf_num;

	pr_info("video=h[%d,%d,%d,%d] v[%d,%d,%d,%d] pclk=%d lane=%d intf=%d\n",
		video_cfg->h_active, video_cfg->h_front_porch,
		video_cfg->h_pulse_width, video_cfg->h_back_porch,
		video_cfg->v_active, video_cfg->v_front_porch,
		video_cfg->v_pulse_width, video_cfg->v_back_porch,
		video_cfg->pclk_khz, video_cfg->num_of_lanes,
		video_cfg->num_of_intfs);

	rc = drm_hdmi_avi_infoframe_from_display_mode(&avi_frame, mode, false);
	if (rc) {
		pr_err("get avi frame failed ret=%d\n", rc);
	} else {
		video_cfg->scaninfo = avi_frame.scan_mode;
		video_cfg->ar = avi_frame.picture_aspect;
		video_cfg->vic = avi_frame.video_code;

		if ((video_cfg->h_active == 3840) && (video_cfg->v_active == 2160))
			video_cfg->vic = VIC_FIX_4k30;

		pr_info("scaninfo=%d ar=%d vic=%d\n",
			video_cfg->scaninfo, video_cfg->ar, video_cfg->vic);
	}
}

/* connector funcs */
static enum drm_connector_status
lt9611_connector_detect(struct drm_connector *connector, bool force)
{
	struct lt9611 *pdata = connector_to_lt9611(connector);

	if (force) {
		int connected = pdata->hpd_status;

		pdata->status = connected ?  connector_status_connected :
			connector_status_disconnected;

		pr_info("@lt9611 connected(%d)\n", connected);
	} else
		pdata->status = connector_status_connected;

	return pdata->status;
}

static int lt9611_read_edid(struct lt9611 *pdata)
{
	int ret = 0;
	u8 i, j;
	u8 temp = 0;

	struct lt9611_reg_cfg reg_cfg[] = {
		{0xff, 0x85},
		{0x03, 0xc9},
		{0x04, 0xa0},
		{0x05, 0x00},
		{0x06, 0x20},
		{0x14, 0x7f},
	};

	struct lt9611_reg_cfg reg_cfg1[] = {
		{0x07, 0x36},
		{0x07, 0x31},
		{0x07, 0x37},
	};

	if (!pdata) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	memset(pdata->edid_buf, 0, EDID_SEG_SIZE);

	lt9611_write_array(pdata, reg_cfg, ARRAY_SIZE(reg_cfg));

	for (i = 0 ; i < 8 ; i++) {
		lt9611_write_byte(pdata, 0x05, i * 32); /* offset address */
		lt9611_write_array(pdata, reg_cfg1, ARRAY_SIZE(reg_cfg1));
		usleep_range(5000, 10000);

		lt9611_read(pdata, 0x40, &temp, 1);

		if (temp & 0x02) {  /*KEY_DDC_ACCS_DONE=1*/
			for (j = 0; j < 32; j++) {
				lt9611_read(pdata, 0x83,
					&(pdata->edid_buf[i*32+j]), 1);
			}
		} else if (temp & 0x50) { /* DDC No Ack or Abitration lost */
			pr_err("read edid failed: no ack\n");
			ret = -EIO;
			goto end;
		} else {
			pr_err("read edid failed: access not done\n");
			ret = -EIO;
			goto end;
		}
	}

	pr_info("@lt9611 read edid succeeded, checksum = 0x%x\n",
		pdata->edid_buf[255]);

end:
	lt9611_write_byte(pdata, 0x07, 0x1f);
	return ret;
}

static int lt9611_get_edid_block(void *data, u8 *buf, unsigned int block,
		size_t len)
{
	struct lt9611 *pdata = data;

	memcpy(buf, pdata->edid_buf + block * 128, len);

	return 0;
}

#define MODE_SIZE(m) ((m)->hdisplay * (m)->vdisplay)
#define MODE_REFRESH_DIFF(c, t) (abs((c) - (t)))

static void lt9611_choose_best_mode(struct drm_connector *connector)
{
	struct drm_display_mode *t, *cur_mode, *preferred_mode;
	int cur_vrefresh, preferred_vrefresh;
	int target_refresh = 60;

	if (list_empty(&connector->probed_modes))
		return;

	preferred_mode = list_first_entry(&connector->probed_modes,
		struct drm_display_mode, head);
	list_for_each_entry_safe(cur_mode, t, &connector->probed_modes, head) {
		cur_mode->type &= ~DRM_MODE_TYPE_PREFERRED;
		if (cur_mode == preferred_mode)
			continue;

		/*Largest mode is preferred*/
		if (MODE_SIZE(cur_mode) > MODE_SIZE(preferred_mode))
			preferred_mode = cur_mode;

		cur_vrefresh = cur_mode->vrefresh ?
			cur_mode->vrefresh : drm_mode_vrefresh(cur_mode);

		preferred_vrefresh = preferred_mode->vrefresh ?
			preferred_mode->vrefresh :
			drm_mode_vrefresh(preferred_mode);

		/*At a given size, try to get closest to target refresh*/
		if ((MODE_SIZE(cur_mode) == MODE_SIZE(preferred_mode)) &&
			MODE_REFRESH_DIFF(cur_vrefresh, target_refresh) <
			MODE_REFRESH_DIFF(preferred_vrefresh, target_refresh) &&
			cur_vrefresh <= target_refresh) {
			preferred_mode = cur_mode;
		}
	}

	preferred_mode->type |= DRM_MODE_TYPE_PREFERRED;
}

static void lt9611_set_preferred_mode(struct drm_connector *connector)
{
	struct lt9611 *pdata = connector_to_lt9611(connector);
	struct drm_display_mode *mode,  *last_mode;
	const char *string;

	if (pdata->edid) {
		lt9611_choose_best_mode(connector);
	} else {
		/* use specified mode as preferred */
		if (!of_property_read_string(pdata->dev->of_node,
			"lt,preferred-mode", &string)) {
			list_for_each_entry(mode, &connector->probed_modes, head) {
				if (!strcmp(mode->name, string))
					mode->type |= DRM_MODE_TYPE_PREFERRED;
			}
		} else {
			list_for_each_entry(mode, &connector->probed_modes, head) {
				last_mode = mode;
			}
			last_mode->type |= DRM_MODE_TYPE_PREFERRED;
		}
	}
}

static int lt9611_connector_get_modes(struct drm_connector *connector)
{
	struct lt9611 *pdata = connector_to_lt9611(connector);
	struct drm_display_mode *mode, *m;
	unsigned int count = 0;

	if (pdata->edid) {
		drm_connector_update_edid_property(connector,
			pdata->edid);

		count = drm_add_edid_modes(connector, pdata->edid);
	} else {
		list_for_each_entry(mode, &pdata->mode_list, head) {
			m = drm_mode_duplicate(connector->dev, mode);
			if (!m) {
				pr_err("failed to add hdmi mode %dx%d\n",
					mode->hdisplay, mode->vdisplay);
				break;
			}
			drm_mode_probed_add(connector, m);
		}
		count = pdata->num_of_modes;
	}

	lt9611_set_preferred_mode(connector);

	return count;
}

static enum drm_mode_status lt9611_connector_mode_valid(
		struct drm_connector *connector, struct drm_display_mode *drm_mode)
{
	struct lt9611 *pdata = connector_to_lt9611(connector);
	struct drm_display_mode *mode, *n, *m, *mode_list;
	bool mode_exist = false;

	drm_mode->vrefresh = drm_mode_vrefresh(drm_mode);

	list_for_each_entry_safe(mode, n, &pdata->mode_list, head) {
		if (drm_mode->vdisplay == mode->vdisplay &&
			drm_mode->hdisplay == mode->hdisplay &&
			drm_mode->vrefresh == mode->vrefresh &&
			drm_mode->clock == mode->clock) {
			list_for_each_entry(mode_list, &pdata->support_mode_list, head) {
				if (mode_list->vdisplay == drm_mode->vdisplay &&
					mode_list->hdisplay == drm_mode->hdisplay &&
					mode_list->vrefresh == drm_mode->vrefresh) {
					mode_exist = true;
					break;
				}
			}

			if (!mode_exist) {
				m = kzalloc(sizeof(*m), GFP_KERNEL);
				if (!m) {
					pr_err("Out of memory\n");
					return -ENOMEM;
				}
				m->vdisplay = drm_mode->vdisplay;
				m->hdisplay = drm_mode->hdisplay;
				m->vrefresh = drm_mode->vrefresh;
				list_add_tail(&m->head, &pdata->support_mode_list);
			}

			if (drm_mode->vdisplay == pdata->debug_mode.vdisplay &&
				drm_mode->hdisplay == pdata->debug_mode.hdisplay &&
				drm_mode->vrefresh == pdata->debug_mode.vrefresh &&
				pdata->fix_mode)
				return MODE_OK;

			if (!pdata->fix_mode)
				return MODE_OK;
		}
	}

	return MODE_BAD;
}

/* bridge funcs */
static void lt9611_bridge_enable(struct drm_bridge *bridge)
{
	struct lt9611 *pdata = bridge_to_lt9611(bridge);

	pr_info("@lt9611 bridge enable\n");

	if (pdata->lt9611_func->video_on) {
		if (pdata->lt9611_func->video_on(pdata, true)) {
			pr_err("video on failed\n");
			return;
		}
	}
}

static void lt9611_bridge_disable(struct drm_bridge *bridge)
{
	pr_info("@lt9611 bridge disable\n");
}

static void lt9611_bridge_mode_set(struct drm_bridge *bridge,
		struct drm_display_mode *mode,
		struct drm_display_mode *adj_mode)
{
	struct lt9611 *pdata = bridge_to_lt9611(bridge);
	struct lt9611_video_cfg *video_cfg = &pdata->video_cfg;
	int ret = 0;

	pr_info("@lt9611 bridge mode_set: hdisplay=%d, vdisplay=%d, vrefresh=%d, clock=%d\n",
		adj_mode->hdisplay, adj_mode->vdisplay,
		adj_mode->vrefresh, adj_mode->clock);

	drm_mode_copy(&pdata->curr_mode, adj_mode);

	if (pdata->lt9611_func->video_cfg)  {
		memset(video_cfg, 0, sizeof(struct lt9611_video_cfg));
		pdata->lt9611_func->video_cfg(pdata, adj_mode, video_cfg);

		/* TODO: update intf number of host */
		if (video_cfg->num_of_lanes != pdata->dsi->lanes) {
			mipi_dsi_detach(pdata->dsi);
			pdata->dsi->lanes = video_cfg->num_of_lanes;
			ret = mipi_dsi_attach(pdata->dsi);
			if (ret)
				pr_warn("failed to change host lanes\n");
		}
	}
}

static const struct drm_connector_helper_funcs lt9611_connector_helper_funcs = {
	.get_modes = lt9611_connector_get_modes,
	.mode_valid = lt9611_connector_mode_valid,
};

static const struct drm_connector_funcs lt9611_connector_funcs = {
	.fill_modes = drm_helper_probe_single_connector_modes,
	.detect = lt9611_connector_detect_com,
	.destroy = drm_connector_cleanup,
	.reset = drm_atomic_helper_connector_reset,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

static int lt9611_bridge_attach(struct drm_bridge *bridge)
{
	struct mipi_dsi_host *host;
	struct mipi_dsi_device *dsi;
	struct lt9611 *pdata = bridge_to_lt9611(bridge);
	int ret;
	const struct mipi_dsi_device_info info = {
		.type = "lt9611",
		.channel = 0,
		.node = NULL,
	};

	pr_info("@lt9611 bridge attach\n");

	if (!bridge->encoder) {
		DRM_ERROR("Parent encoder object not found");
		return -ENODEV;
	}

	ret = drm_connector_init(bridge->dev, &pdata->connector,
		&lt9611_connector_funcs,
		DRM_MODE_CONNECTOR_HDMIA);
	if (ret) {
		DRM_ERROR("Failed to initialize connector: %d\n", ret);
		return ret;
	}

	drm_connector_helper_add(&pdata->connector,
		&lt9611_connector_helper_funcs);

	ret = drm_connector_register(&pdata->connector);
	if (ret) {
		DRM_ERROR("Failed to register connector: %d\n", ret);
		return ret;
	}

	pdata->connector.polled = DRM_CONNECTOR_POLL_CONNECT;

	ret = drm_connector_attach_encoder(&pdata->connector,
		bridge->encoder);
	if (ret) {
		DRM_ERROR("Failed to link up connector to encoder: %d\n", ret);
		return ret;
	}

	host = of_find_mipi_dsi_host_by_node(pdata->host_node);
	if (!host) {
		pr_err("failed to find dsi host\n");
		return -EPROBE_DEFER;
	}

	dsi = mipi_dsi_device_register_full(host, &info);
	if (IS_ERR(dsi)) {
		pr_err("failed to create dsi device\n");
		ret = PTR_ERR(dsi);
		goto err_dsi_device;
	}

	dsi->lanes = 4;
	dsi->format = MIPI_DSI_FMT_RGB888;
	dsi->mode_flags = MIPI_DSI_MODE_VIDEO | MIPI_DSI_MODE_VIDEO_SYNC_PULSE |
		MIPI_DSI_MODE_VIDEO_HSE | MIPI_DSI_MODE_VIDEO_BLLP |
		MIPI_DSI_MODE_VIDEO_EOF_BLLP;

	ret = mipi_dsi_attach(dsi);
	if (ret < 0) {
		pr_err("failed to attach dsi to host\n");
		goto err_dsi_attach;
	}

	pdata->dsi = dsi;
	pdata->bridge_attach = true;

	/* Add wq for bootup edid adaption */
	queue_work(pdata->wq, &pdata->work);

	return 0;

err_dsi_attach:
	mipi_dsi_device_unregister(dsi);
err_dsi_device:
	return ret;
}

static void lt9611_bridge_pre_enable(struct drm_bridge *bridge)
{
	struct lt9611 *pdata = bridge_to_lt9611(bridge);

	pr_info("@lt9611 bridge pre_enable\n");

	if (pdata->lt9611_func->video_update) {
		if (pdata->lt9611_func->video_update(pdata)) {
			pr_err("video on failed\n");
			return;
		}
	}
}

static bool lt9611_bridge_mode_fixup(struct drm_bridge *bridge,
		const struct drm_display_mode *mode,
		struct drm_display_mode *adjusted_mode)
{
	pr_debug("@Lt9611 bridge mode_fixup\n");

	return true;
}

static void lt9611_bridge_post_disable(struct drm_bridge *bridge)
{
	pr_debug("@lt9611_bridge bridge post disable\n");
}

static const struct drm_bridge_funcs lt9611_bridge_funcs = {
	.attach			= lt9611_bridge_attach,
	.mode_fixup		= lt9611_bridge_mode_fixup,
	.pre_enable		= lt9611_bridge_pre_enable,
	.enable			= lt9611_bridge_enable,
	.disable		= lt9611_bridge_disable,
	.post_disable	= lt9611_bridge_post_disable,
	.mode_set		= lt9611_bridge_mode_set,
};

static const struct lt9611_chip_funcs lt9611_funcs = {
	.reset_chip		= lt9611_reset,
	.init_setup		= lt9611_init_setup,
	.irq_handle		= lt9611_irq_thread_handler,
	.detect			= lt9611_connector_detect,
	.video_cfg		= lt9611_set_video_cfg,
	.read_edid		= lt9611_read_edid,
	.video_update	= lt9611_video_update,
	.video_on		= lt9611_video_on,
};

static int lt9611_parse_dt(struct device *dev,
		struct lt9611 *pdata)
{
	struct device_node *np = dev->of_node;
	struct device_node *end_node, *port = NULL, *child = NULL, *remote = NULL;
	int ret = 0, count = 0;

	end_node = of_graph_get_endpoint_by_regs(dev->of_node, 0, 0);
	if (!end_node) {
		pr_err("remote endpoint not found\n");
		return -ENODEV;
	}

	pdata->host_node = of_graph_get_remote_port_parent(end_node);
	of_node_put(end_node);
	if (!pdata->host_node) {
		pr_err("remote node not found\n");
		return -ENODEV;
	}
	of_node_put(pdata->host_node);

	pdata->irq_gpio =
		of_get_named_gpio(np, "lt,irq-gpio", 0);
	if (!gpio_is_valid(pdata->irq_gpio)) {
		pr_err("irq gpio not specified\n");
		ret = -EINVAL;
	}
	pr_debug("irq_gpio=%d\n", pdata->irq_gpio);

	pdata->reset_gpio =
		of_get_named_gpio(np, "lt,reset-gpio", 0);
	if (!gpio_is_valid(pdata->reset_gpio)) {
		pr_err("reset gpio not specified\n");
		ret = -EINVAL;
	}
	pr_debug("reset_gpio=%d\n", pdata->reset_gpio);

	pdata->hdmi_ps_gpio =
		of_get_named_gpio(np, "lt,hdmi-ps-gpio", 0);
	if (!gpio_is_valid(pdata->hdmi_ps_gpio))
		pr_debug("hdmi ps gpio not specified\n");
	else
		pr_debug("hdmi_ps_gpio=%d\n", pdata->hdmi_ps_gpio);

	pdata->hdmi_en_gpio =
		of_get_named_gpio(np, "lt,hdmi-en-gpio", 0);
	if (!gpio_is_valid(pdata->hdmi_en_gpio))
		pr_debug("hdmi en gpio not specified\n");
	else
		pr_debug("hdmi_en_gpio=%d\n", pdata->hdmi_en_gpio);

	pdata->ac_mode = of_property_read_bool(np, "lt,ac-mode");
	pr_debug("ac_mode=%d\n", pdata->ac_mode);

	if (of_property_read_bool(np, "lt,lt9611"))
	{
		pdata->lt9611_func = &lt9611_funcs;
	} else {
		pr_err("not define lt9611 chip\n");
		return -ENODEV;
	}

	port = of_get_child_by_name(np, "ports");
	if (!port)
		pr_err("not found port\n");

	for_each_endpoint_of_node(port, child) {
		remote = of_graph_get_remote_port(child);
		if (!remote)
			pr_err("not find remote\n");
		count++;
	}

	pdata->intf_num = count;

	INIT_LIST_HEAD(&pdata->mode_list);
	lt9611_parse_dt_modes(np,
		&pdata->mode_list, &pdata->num_of_modes);

	return ret;
}

/* sysfs */
static ssize_t dump_info_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;
	struct lt9611 *pdata = dev_get_drvdata(dev);

	len += snprintf(buf + len, (PAGE_SIZE - len), "======= hdmi lt9611 debug ========\n");
	len += snprintf(buf + len, (PAGE_SIZE - len), "i2c(%x) modes(%d) pluggable(%d) intf_num(%d)\n",
		pdata->i2c_addr, pdata->num_of_modes, pdata->non_pluggable, pdata->intf_num);
	len += snprintf(buf + len, (PAGE_SIZE - len), "hdmi(%d) edid_complete(%d) bridge(%d) hpd(%d)\n",
		pdata->hdmi_mode, pdata->edid_complete, pdata->bridge_attach, pdata->hpd_status);
	len += snprintf(buf + len, (PAGE_SIZE - len), "pending_edid(%d) edid(%d) hpd_trig(%d) fix(%d)\n",
		pdata->pending_edid, pdata->edid_status, pdata->hpd_trigger, pdata->fix_mode);
	len += snprintf(buf + len, (PAGE_SIZE - len), "cur_mode(%dx%d@%d)\n", pdata->curr_mode.hdisplay,
		pdata->curr_mode.vdisplay, pdata->curr_mode.vrefresh);
	len += snprintf(buf + len, (PAGE_SIZE - len), "Real Hpd(%d)\n", lt9611_hpd_status(pdata));

	return len;
}

static ssize_t dump_info_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	int num = 0;
	struct lt9611 *pdata = dev_get_drvdata(dev);

	if (!pdata) {
		pr_err("pdata is NULL\n");
		return -EINVAL;
	}

	for (num = 0; num < 2; num++) {
		print_hex_dump(KERN_WARNING,
			"", DUMP_PREFIX_NONE, 16, 1,
			pdata->edid_buf + num * 128,
			EDID_LENGTH, false);
	}

	return count;
}


static ssize_t edid_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	struct lt9611 *pdata = dev_get_drvdata(dev);

	return scnprintf(buf, PAGE_SIZE, "%dx%d@%d\n", pdata->curr_mode.hdisplay,
		pdata->curr_mode.vdisplay, pdata->curr_mode.vrefresh);
}

static ssize_t edid_mode_store(struct device *dev,
	struct device_attribute *attr, const char *buf,
	size_t count)
{
	int hdisplay = 0, vdisplay = 0, vrefresh = 0;
	struct lt9611 *pdata = dev_get_drvdata(dev);

	if (!pdata)
		goto err;

	if (sscanf(buf, "%d %d %d", &hdisplay, &vdisplay, &vrefresh) != 3)
		goto err;

	if (!hdisplay || !vdisplay || !vrefresh)
		goto err;

	pdata->fix_mode = true;
	pdata->debug_mode.hdisplay = hdisplay;
	pdata->debug_mode.vdisplay = vdisplay;
	pdata->debug_mode.vrefresh = vrefresh;

	pr_debug("fixed mode hdisplay=%d vdisplay=%d, vrefresh=%d\n",
		hdisplay, vdisplay, vrefresh);
	return count;

err:
	pdata->fix_mode = false;
	return -EINVAL;
}

static ssize_t hdmi_mode_list_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct lt9611 *pdata = dev_get_drvdata(dev);
	struct drm_display_mode *mode;
	int len = 0, size = 0;

	list_for_each_entry(mode, &pdata->support_mode_list, head) {
		len = scnprintf(buf, PAGE_SIZE - size, "%dx%d@%d\n",
			mode->hdisplay, mode->vdisplay, mode->vrefresh);
		size += len;
		buf += len;
	}

	return size;
}

void lt9611_video_check(struct lt9611 *pdata)
{
	u8 mipi_video_format = 0x00;
	u16 h_act_a, h_act_b, v_act, v_tal;
	u16 h_total_sysclk;
	u8 tmpH, tmpL;

	lt9611_write_byte(pdata, 0xff, 0x82);

	lt9611_read(pdata, 0x86, &tmpH, 1);
	lt9611_read(pdata, 0x87, &tmpL, 1);
	h_total_sysclk = (tmpH<<8) + tmpL;
	pr_info("@lt9611 LT9611_Video_Check: h_total_sysclk = %d\n", h_total_sysclk);

	lt9611_read(pdata, 0x82, &tmpH, 1);
	lt9611_read(pdata, 0x83, &tmpL, 1);
	v_act = (tmpH<<8) + tmpL;

	lt9611_read(pdata, 0x6c, &tmpH, 1);
	lt9611_read(pdata, 0x6d, &tmpL, 1);
	v_tal = (tmpH<<8) + tmpL;

	lt9611_write_byte(pdata, 0xff, 0x83);

	lt9611_read(pdata, 0x82, &tmpH, 1);
	lt9611_read(pdata, 0x83, &tmpL, 1);
	h_act_a = (tmpH<<8) + tmpL;

	lt9611_read(pdata, 0x86, &tmpH, 1);
	lt9611_read(pdata, 0x87, &tmpL, 1);
	h_act_b = (tmpH<<8) + tmpL;

	pr_info("@lt9611 LT9611_Video_Check: lt9611.input_color_space = RGB888\n");
	h_act_a /= 3;
	h_act_b /= 3;

	lt9611_read(pdata, 0x88, &tmpH, 1);

	mipi_video_format = tmpH;

	pr_info("@lt9611 Video_Check: h_act_a, h_act_b, v_act, v_tal: %d, %d, %d, %d,\n", h_act_a, h_act_b, v_act, v_tal);
	pr_info("@lt9611 Video_Check: mipi_video_format: 0x%x\n", mipi_video_format);
}


void lt9611_freq_meter_bype_clk(struct lt9611 *pdata)
{
	u8 temp;
	u32 reg = 0x00;

	pr_info("@lt9611 freq_meter_bype_clk debug\n");
	/* port A byte clk meter */
	lt9611_write_byte(pdata, 0xff, 0x82);
	lt9611_write_byte(pdata, 0xc7, 0x03);	//PortA
	msleep(50);

	lt9611_read(pdata, 0xcd, &temp, 1);

	if ((temp&0x60) == 0x60) /* clk stable */
	{
		reg = (u32)(temp&0x0f)*65536;
		lt9611_read(pdata, 0xce, &temp, 1);
		reg = reg + (u16)temp*256;
		lt9611_read(pdata, 0xcf, &temp, 1);
		reg = reg + temp;
		pr_info("@lt9611 port A byte clk = %d\n", reg);
	} else /* clk unstable */
		pr_err("@lt9611 port A byte clk unstable\n");

	/* port B byte clk meter */
	lt9611_write_byte(pdata, 0xff, 0x82);
	lt9611_write_byte(pdata, 0xc7, 0x04);
	msleep(50);
	lt9611_read(pdata, 0xcd, &temp, 1);
	if ((temp&0x60) == 0x60) /* clk stable */
	{
		reg = (u32)(temp&0x0f)*65536;
		lt9611_read(pdata, 0xce, &temp, 1);
		reg = reg + (u16)temp*256;
		lt9611_read(pdata, 0xcf, &temp, 1);
		reg = reg + temp;
		pr_info("@lt9611 port B byte clk = %d\n", reg);
	} else /* clk unstable */
	    pr_err("@lt9611 port B byte clk unstable\n");
}

void lt9611_htotal_sysclk(struct lt9611 *pdata)
{
	u16 reg;
	u8 loopx, tmpH, tmpL;

	for (loopx = 0; loopx < 10; loopx++)
	{
		lt9611_write_byte(pdata, 0xff, 0x82);
		lt9611_read(pdata, 0x86, &tmpH, 1);
		lt9611_read(pdata, 0x87, &tmpL, 1);

		reg = tmpH*256 + tmpL;
		pr_info("@lt9611 Htotal_Sysclk = %d\n", reg);
	}
}

void lt9611_pcr_mk_debug(struct lt9611 *pdata)
{
	u8 loopx, tmp;

	for (loopx = 0; loopx < 8; loopx++)
	{
		lt9611_write_byte(pdata, 0xff, 0x83);
		lt9611_read(pdata, 0x97, &tmp, 1);
		pr_info("@lt9611 M:0x%x\n", tmp);

		lt9611_read(pdata, 0xb4, &tmp, 1);
		pr_info(" 0x%x\n", tmp);

		lt9611_read(pdata, 0xb5, &tmp, 1);
		pr_info(" 0x%x\n", tmp);

		lt9611_read(pdata, 0xb6, &tmp, 1);
		pr_info(" 0x%x\n", tmp);

		lt9611_read(pdata, 0xb7, &tmp, 1);
		pr_info(" 0x%x\n", tmp);

		msleep(1000);
	}
}

void lt9611_dphy_debug(struct lt9611 *pdata)
{
	u8 temp;

	lt9611_write_byte(pdata, 0xff, 0x83);
	lt9611_read(pdata, 0xbc, &temp, 1);
	if (temp == 0x55)
		pr_info("@lt9611 port A lane PN is right");
	else
		pr_err("@lt9611 port A lane PN error 0x83bc = 0x%x", temp);

	lt9611_read(pdata, 0x99, &temp, 1);
	if (temp == 0xb8)
		pr_info("@lt9611 port A lane 0 sot right\n");
	else
		pr_err("@lt9611 port A lane 0 sot error = 0x%x\n", temp);

	lt9611_read(pdata, 0x9b, &temp, 1);
	if (temp == 0xb8)
		pr_info("@lt9611 port A lane 1 sot right\n");
	else
		pr_err("@lt9611 port A lane 1 sot error = 0x%x\n", temp);

	lt9611_read(pdata, 0x9d, &temp, 1);
	if (temp == 0xb8)
		pr_info("@lt9611 port A lane 2 sot right \n");
	else
		pr_err("@lt9611 port A lane 2 sot error = 0x%x\n", temp);

	lt9611_read(pdata, 0x9f, &temp, 1);
	if (temp == 0xb8)
		pr_info("@lt9611 port A lane 3 sot right\n");
	else
		pr_err("@lt9611 port A lane 3 sot error = 0x%x\n", temp);

	lt9611_read(pdata, 0x98, &temp, 1);
	pr_info("@lt9611 port A lane 0 settle = 0x%x\n", temp);

	lt9611_read(pdata, 0x9a, &temp, 1);
	pr_info("@lt9611 port A lane 1 settle = 0x%x\n", temp);

	lt9611_read(pdata, 0x9c, &temp, 1);
	pr_info("@lt9611 port A lane 2 settle = 0x%x\n", temp);

	lt9611_read(pdata, 0x9e, &temp, 1);
	pr_info("@lt9611 port A lane 3 settle = 0x%x\n", temp);
}


/* sysfs */
static ssize_t debug_mode_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	ssize_t len = 0;

	len += snprintf(buf + len, (PAGE_SIZE - len),
		"=== hdmi debug traning ========\n");
	len += snprintf(buf + len, (PAGE_SIZE - len),
		"echo [index] [ext_param] > debug_mode\n");
	len += snprintf(buf + len, (PAGE_SIZE - len),
		"0 clr hpd | 1 self check | 2 hpd debounce\n");

	return len;
}

static ssize_t debug_mode_store(struct device *dev,
		struct device_attribute *attr,
		const char *buf,
		size_t count)
{
	int dbg_index = 0;
	int param = 0;
	struct lt9611 *pdata = dev_get_drvdata(dev);
	struct lt9611_reg_cfg clr_irq3[] = {
		{0xff, 0x82},	/* irq 3 clear flag */
		{0x07, 0xff},
		{0x07, 0x3f},
	};

	if (!pdata) {
		pr_err("pdata is NULL\n");
		return -EINVAL;
	}

	if (sscanf(buf, "%d %d", &dbg_index, &param) != 2)
		goto err;

	switch (dbg_index) {
	case 0:
		pr_info("clr interrupt bit\n");
		lt9611_write_array(pdata, clr_irq3, ARRAY_SIZE(clr_irq3));
		break;
	case 1:
		lt9611_video_check(pdata);
		lt9611_freq_meter_bype_clk(pdata);
		lt9611_htotal_sysclk(pdata);
		lt9611_pcr_mk_debug(pdata);
		lt9611_dphy_debug(pdata);
		break;
	case 2:
		/* hpd debounce */
		pr_info("hpd debounce 0x59(%x)\n", param);
		lt9611_write_byte(pdata, 0xff, 0x82);
		lt9611_write_byte(pdata, 0x59, param);
		break;
	default:
		pr_err("mode unsupport\n");
		break;
	}

	return count;

err:
	return -EINVAL;
}

//static DEVICE_ATTR(lt9611_dump_info, 0200, NULL, lt9611_dump_info_wta_attr);
static DEVICE_ATTR_RW(dump_info);
static DEVICE_ATTR_RW(edid_mode);
static DEVICE_ATTR_RO(hdmi_mode_list);
static DEVICE_ATTR_RW(debug_mode);

static struct attribute *lt9611_sysfs_attrs[] = {
	&dev_attr_dump_info.attr,
	&dev_attr_edid_mode.attr,
	&dev_attr_hdmi_mode_list.attr,
	&dev_attr_debug_mode.attr,
	NULL,
};

static struct attribute_group lt9611_sysfs_attr_grp = {
	.attrs = lt9611_sysfs_attrs,
};

static int lt9611_sysfs_init(struct device *dev)
{
	int rc = 0;

	if (!dev) {
		pr_err("%s: Invalid params\n", __func__);
		return -EINVAL;
	}

	rc = sysfs_create_group(&dev->kobj, &lt9611_sysfs_attr_grp);
	if (rc)
		pr_err("%s: sysfs group creation failed %d\n", __func__, rc);

	return rc;
}

static void lt9611_sysfs_remove(struct device *dev)
{
	if (!dev) {
		pr_err("%s: Invalid params\n", __func__);
		return;
	}

	sysfs_remove_group(&dev->kobj, &lt9611_sysfs_attr_grp);
}

static int lt9611_probe(struct i2c_client *client,
		const struct i2c_device_id *id)
{
	struct lt9611 *pdata;
	int ret = 0;

	if (!client || !client->dev.of_node) {
		pr_err("invalid input\n");
		return -EINVAL;
	}

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		pr_err("device doesn't support I2C\n");
		return -ENODEV;
	}

	pr_info("@lt9611 lt9611_probe enter\n");

	pdata = devm_kzalloc(&client->dev,
		sizeof(struct lt9611), GFP_KERNEL);
	if (!pdata)
		return -ENOMEM;

	ret = lt9611_parse_dt(&client->dev, pdata);
	if (ret) {
		pr_err("failed to parse device tree\n");
		goto err_dt_parse;
	}

	ret = lt9611_get_dt_supply(&client->dev, pdata);
	if (ret) {
		pr_err("failed to get dt supply\n");
		goto err_dt_parse;
	}

	pdata->dev = &client->dev;
	pdata->i2c_client = client;

	ret = lt9611_gpio_configure(pdata, true);
	if (ret) {
		pr_err("failed to configure GPIOs\n");
		goto err_dt_supply;
	}

	ret = lt9611_enable_vreg(pdata, true);
	if (ret) {
		pr_err("failed to enable vreg\n");
		goto err_dt_supply;
	}

	lt9611_power_on(pdata, 1);

	i2c_set_clientdata(client, pdata);
	dev_set_drvdata(&client->dev, pdata);

	pStdata = pdata;

	ret = lt9611_sysfs_init(&client->dev);
	if (ret) {
		pr_err("sysfs init failed\n");
		goto err_i2c_prog;
	}

	ret = lt9611_read_chip_id(pdata);
	if (ret) {
		pr_err("failed to read chip rev\n");
		goto err_i2c_prog;
	}

	mutex_init(&pdata->lock);
	init_waitqueue_head(&pdata->edid_wq);

#if IS_ENABLED(CONFIG_OF)
	pdata->bridge.of_node = client->dev.of_node;
#endif

	pdata->bridge.funcs = &lt9611_bridge_funcs;

	drm_bridge_add(&pdata->bridge);

	pdata->wq = create_singlethread_workqueue("lt9611_wk");
	if (!pdata->wq) {
		pr_err("Error creating lt9611 wq\n");
		return -ENOMEM;
	}

	INIT_WORK(&pdata->work, lt9611_hpd_work);

	lt9611_init_setup(pdata);

	pdata->irq = gpio_to_irq(pdata->irq_gpio);
	ret = request_threaded_irq(pdata->irq, NULL, pdata->lt9611_func->irq_handle,
		IRQF_TRIGGER_FALLING | IRQF_ONESHOT, "lt9611_irq", pdata);
	if (ret) {
		pr_err("failed to request irq\n");
		goto err_i2c_prog;
	}

	pr_info("@lt9611 lt9611_probe success\n");

	INIT_LIST_HEAD(&pdata->support_mode_list);
	return 0;

err_i2c_prog:
	lt9611_gpio_configure(pdata, false);
err_dt_supply:
	lt9611_put_dt_supply(&client->dev, pdata);
err_dt_parse:
	devm_kfree(&client->dev, pdata);
	return ret;
}

static int lt9611_remove(struct i2c_client *client)
{
	int ret = -EINVAL;
	struct lt9611 *pdata = i2c_get_clientdata(client);
	struct drm_display_mode *mode, *n;

	if (!pdata)
		goto end;

	pr_info("@lt9611 remove !!!\n");

	mipi_dsi_detach(pdata->dsi);
	mipi_dsi_device_unregister(pdata->dsi);

	drm_bridge_remove(&pdata->bridge);

	lt9611_sysfs_remove(&client->dev);

	disable_irq(pdata->irq);
	free_irq(pdata->irq, pdata);

	ret = lt9611_gpio_configure(pdata, false);

	lt9611_put_dt_supply(&client->dev, pdata);


	list_for_each_entry_safe(mode, n, &pdata->mode_list, head) {
		list_del(&mode->head);
		kfree(mode);
	}

	devm_kfree(&client->dev, pdata);

	if (pdata->wq)
		destroy_workqueue(pdata->wq);

end:
	return ret;
}

#ifdef CONFIG_PM_SLEEP
static int lt9611_suspend(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct lt9611 *pdata = i2c_get_clientdata(client);

	pr_info("lt9611 suspend\n");
	if (pdata->regulator_on) {
		lt9611_enable_interrupts(pdata, CFG_HPD_INTERRUPTS, 0);
		lt9611_power_on(pdata, false);
		pdata->regulator_on = false;
	}

	return 0;
}

static int lt9611_resume(struct device *dev)
{
	struct i2c_client *client = to_i2c_client(dev);
	struct lt9611 *pdata = i2c_get_clientdata(client);

	pr_info("lt9611 resume\n");
	if (!pdata->regulator_on) {
		lt9611_power_on(pdata, true);
		lt9611_init_setup(pdata);
		pdata->regulator_on = true;
	}

	return 0;
}

static const struct dev_pm_ops lt9611_pm = {
	SET_SYSTEM_SLEEP_PM_OPS(lt9611_suspend, lt9611_resume)
};
#endif

static struct i2c_device_id lt9611_id[] = {
	{ "lt,lt9611", 0},
	{}
};

static const struct of_device_id lt9611_match_table[] = {
	{.compatible = "lt,lt9611"},
	{}
};
MODULE_DEVICE_TABLE(of, lt9611_match_table);

static struct i2c_driver lt9611_driver = {
	.driver = {
		.name = "lt9611",
		.owner = THIS_MODULE,
#ifdef CONFIG_OF
		.of_match_table = lt9611_match_table,
#endif
#ifdef CONFIG_PM_SLEEP
		.pm = &lt9611_pm,
#endif
	},
	.probe = lt9611_probe,
	.remove = lt9611_remove,
	.id_table = lt9611_id,
};

static int __init lt9611_init(void)
{
	return i2c_add_driver(&lt9611_driver);
}

static void __exit lt9611_exit(void)
{
	i2c_del_driver(&lt9611_driver);
}

module_init(lt9611_init);
module_exit(lt9611_exit);

