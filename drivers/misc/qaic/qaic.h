/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2019, The Linux Foundation. All rights reserved.
 */

#ifndef QAICINTERNAL_H_
#define QAICINTERNAL_H_

#include <linux/cdev.h>
#include <linux/mhi.h>
#include <linux/mutex.h>
#include <linux/pci.h>

#define QAIC_NUM_DBC		16
#define QAIC_DBC_REQ_ELEM_SIZE	0x40
#define QAIC_DBC_RSP_ELEM_SIZE	0x4

struct dma_bridge_chan {
	void *req_q_base; /* also the base of the entire memory allocation */
	void *rsp_q_base;
	dma_addr_t dma_addr;
	u32 total_size;
	u32 nelem;
};

struct qaic_device {
	struct pci_dev		*pdev;
	int			bars;
	void __iomem		*bar_0;
	struct mhi_controller	*mhi_cntl;
	struct mhi_device	*cntl_ch;
	struct list_head	cntl_xfer_list;
	u32			next_seq_num;
	struct mutex		cntl_mutex;
	bool			cntl_lost_buf;
	struct cdev		cdev;
	struct device		*dev;
	struct dma_bridge_chan	dbc[QAIC_NUM_DBC];
};

int qaic_manage_ioctl(struct qaic_device *qdev, unsigned long arg);

void qaic_mhi_ul_xfer_cb(struct mhi_device *mhi_dev,
			 struct mhi_result *mhi_result);

void qaic_mhi_dl_xfer_cb(struct mhi_device *mhi_dev,
			 struct mhi_result *mhi_result);

int qaic_control_open(struct qaic_device *qdev);
void qaic_control_close(struct qaic_device *qdev);
#endif /* QAICINTERNAL_H_ */
