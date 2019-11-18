// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2019, The Linux Foundation. All rights reserved. */

#include <linux/err.h>
#include <linux/memblock.h>
#include <linux/mhi.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>

static unsigned int mhi_timeout = 20000; /* 20 sec default */
module_param(mhi_timeout, uint, 0600);

static struct mhi_channel_config aic100_channels[] = {
        {
		.num = 0,
		.name = "LOOPBACK",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 1,
		.name = "LOOPBACK",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 2,
		.name = "SAHARA",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_SBL,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 3,
		.name = "SAHARA",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_SBL,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 4,
		.name = "DIAG",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 5,
		.name = "DIAG",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 6,
		.name = "SSR",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 7,
		.name = "SSR",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 8,
		.name = "QDSS",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 9,
		.name = "QDSS",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 10,
		.name = "CONTROL",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 11,
		.name = "CONTROL",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 12,
		.name = "LOGGING",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 13,
		.name = "LOGGING",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 14,
		.name = "STATUS",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 15,
		.name = "STATUS",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 16,
		.name = "TELEMETRY",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 17,
		.name = "TELEMETRY",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 18,
		.name = "DEBUG",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_TO_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
        {
		.num = 19,
		.name = "DEBUG",
		.num_elements = 32,
		.event_ring = 0,
		.dir = DMA_FROM_DEVICE,
		.ee = MHI_EE_AMSS,
		.pollcfg = 0,
		.data_type = MHI_XFER_BUFFER,
		.doorbell = MHI_BRSTMODE_DISABLE,
		.lpm_notify = false,
		.offload_channel = false,
		.doorbell_mode_switch = false,
		.auto_queue = false,
		.auto_start = false,
	},
};

static struct mhi_event_config aic100_events[] = {
	{
		.num_elements = 32,
		.irq_moderation_ms = 0,
		.msi = 0,
		.channel = 0,
		.mode = MHI_BRSTMODE_DISABLE,
		.data_type = MHI_ER_CTRL_ELEMENT_TYPE,
		.hardware_event = false,
		.client_managed = false,
		.offload_channel = false,
	},
};

static struct mhi_controller_config aic100_config = {
	.max_channels = 128,
	.timeout_ms = 0, /* controlled by mhi_timeout */
	.use_bounce_buf = false,
	.buf_len = 0,
	.num_channels = ARRAY_SIZE(aic100_channels),
	.ch_cfg = aic100_channels,
	.num_events = ARRAY_SIZE(aic100_events),
	.event_cfg = aic100_events,
	.time_sync = false,
	.time_er_index = 0,
};

static int mhi_link_status(struct mhi_controller *mhi_cntl, void *priv)
{
	return 0;
}

static int mhi_runtime_get(struct mhi_controller *mhi_cntl, void *priv)
{
	return 0;
}

static void mhi_runtime_put(struct mhi_controller *mhi_cntl, void *priv)
{
}

static void mhi_status_cb(struct mhi_controller *mhi_cntl,
			  void *priv,
			  enum MHI_CB reason)
{
}

struct mhi_controller *qaic_mhi_register_controller(struct pci_dev *pci_dev,
						    void *mhi_bar,
						    int mhi_irq)
{
	struct mhi_controller *mhi_cntl;
	int ret;

	pci_dbg(pci_dev, "%s\n", __func__);

	mhi_cntl = mhi_alloc_controller(0);
	if (!mhi_cntl)
		return ERR_PTR(-ENOMEM);

	mhi_cntl->dev = &pci_dev->dev;
	mhi_cntl->domain = pci_domain_nr(pci_dev->bus);
	mhi_cntl->dev_id = pci_dev->device;
	mhi_cntl->bus = pci_dev->bus->number;
	mhi_cntl->slot = PCI_SLOT(pci_dev->devfn);

	/*
	 * Covers the entire possible physical ram region.  Remote side is
	 * going to calculate a size of this range, so subtract 1 to prevent
	 * rollover.
	 */
	mhi_cntl->iova_start = 0;
	mhi_cntl->iova_stop = U64_MAX - 1;

	mhi_cntl->status_cb = mhi_status_cb;
	mhi_cntl->runtime_get = mhi_runtime_get;
	mhi_cntl->runtime_put = mhi_runtime_put;
	mhi_cntl->link_status = mhi_link_status;
	mhi_cntl->regs = mhi_bar;
	mhi_cntl->msi_allocated = 1;
	mhi_cntl->irq = kmalloc(sizeof(*mhi_cntl->irq), GFP_KERNEL);

	if (!mhi_cntl->irq)
		return ERR_PTR(-ENOMEM);

	mhi_cntl->irq[0] = mhi_irq;

	mhi_cntl->fw_image = "qcom/aic100/sbl.bin";

	/* use latest configured timeout */
	aic100_config.timeout_ms = mhi_timeout;
	ret = register_mhi_controller(mhi_cntl, &aic100_config);
	if (ret) {
		pci_err(pci_dev, "register_mhi_controller failed %d\n", ret);
		kfree(mhi_cntl->irq);
		mhi_free_controller(mhi_cntl);
		return ERR_PTR(ret);
	}

	ret = mhi_async_power_up(mhi_cntl);
	if (ret) {
		pci_err(pci_dev, "mhi_async_power_up failed %d\n", ret);
		mhi_unregister_mhi_controller(mhi_cntl);
		kfree(mhi_cntl->irq);
		mhi_free_controller(mhi_cntl);
		return ERR_PTR(ret);
	}

	return mhi_cntl;
}

void qaic_mhi_free_controller(struct mhi_controller *mhi_cntl)
{
	mhi_power_down(mhi_cntl, true);
	mhi_unregister_mhi_controller(mhi_cntl);
	kfree(mhi_cntl->irq);
	mhi_free_controller(mhi_cntl);
}
