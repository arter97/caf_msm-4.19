/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2019-2020, The Linux Foundation. All rights reserved.
 */

#ifndef QAICINTERNAL_H_
#define QAICINTERNAL_H_

#include <linux/cdev.h>
#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/kref.h>
#include <linux/mhi.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/wait.h>
#include <linux/workqueue.h>

#define QAIC_NUM_DBC		16
#define QAIC_DBC_BASE		0x20000
#define QAIC_DBC_SIZE		0x1000

#define QAIC_DBC_OFF(i)		((i) * QAIC_DBC_SIZE + QAIC_DBC_BASE)

struct qaic_user {
	pid_t			handle;
	struct qaic_device	*qdev;
	struct list_head	node;
	struct srcu_struct	qdev_lock;
	struct kref		ref_count;
};

struct dma_bridge_chan {
	struct qaic_device	*qdev;
	unsigned int		id;
	/* also the base of the entire memory allocation */
	void			*req_q_base;
	void			*rsp_q_base;
	dma_addr_t		dma_addr;
	u32			total_size;
	u32			nelem;
	struct mutex		mem_lock;
	struct idr		mem_handles;
	struct qaic_user	*usr;
	u16			next_req_id;
	void __iomem		*dbc_base;
	spinlock_t		xfer_lock;
	struct list_head	xfer_list;
	struct srcu_struct	ch_lock;
	struct dentry		*debugfs_root;
	bool			in_use;
	wait_queue_head_t	dbc_release;
};

struct qaic_device {
	struct pci_dev		*pdev;
	int			bars;
	void __iomem		*bar_0;
	void __iomem		*bar_2;
	struct mhi_controller	*mhi_cntl;
	struct mhi_device	*cntl_ch;
	struct list_head	cntl_xfer_list;
	u32			next_seq_num;
	struct mutex		cntl_mutex;
	bool			cntl_lost_buf;
	struct cdev		*cdev;
	struct device		*dev;
	struct dma_bridge_chan	dbc[QAIC_NUM_DBC];
	struct work_struct	reset_work;
	struct work_struct	reset_mhi_work;
	struct workqueue_struct	*cntl_wq;
	bool			in_reset;
	struct srcu_struct	dev_lock;
	struct list_head	users;
	struct mutex		users_mutex;
	struct dentry		*debugfs_root;
	struct device		*hwmon;
	struct mhi_device	*tele_ch;
	struct list_head	tele_xfer_list;
	u32			tele_next_seq_num;
	struct mutex		tele_mutex;
	bool			tele_lost_buf;
	struct workqueue_struct	*tele_wq;
	struct mhi_device	*ras_ch;
};

int get_dbc_req_elem_size(void);
int get_dbc_rsp_elem_size(void);
int get_cntl_version(struct qaic_device *qdev, struct qaic_user *usr,
		     u16 *major, u16 *minor);
int qaic_manage_ioctl(struct qaic_device *qdev, struct qaic_user *usr,
		      unsigned long arg);
int qaic_mem_ioctl(struct qaic_device *qdev, struct qaic_user *usr,
		   unsigned long arg);
int qaic_execute_ioctl(struct qaic_device *qdev, struct qaic_user *usr,
		       unsigned long arg);
int qaic_wait_exec_ioctl(struct qaic_device *qdev, struct qaic_user *usr,
			 unsigned long arg);
int qaic_data_mmap(struct qaic_device *qdev, struct qaic_user *usr,
		   struct vm_area_struct *vma);
void qaic_data_get_fifo_info(struct dma_bridge_chan *dbc, u32 *head,
			     u32 *tail);

void qaic_mhi_ul_xfer_cb(struct mhi_device *mhi_dev,
			 struct mhi_result *mhi_result);

void qaic_mhi_dl_xfer_cb(struct mhi_device *mhi_dev,
			 struct mhi_result *mhi_result);

int qaic_control_open(struct qaic_device *qdev);
void qaic_control_close(struct qaic_device *qdev);
void qaic_release_usr(struct qaic_device *qdev, struct qaic_user *usr);

irqreturn_t dbc_irq_handler(int irq, void *data);
int disable_dbc(struct qaic_device *qdev, u32 dbc_id, struct qaic_user *usr);
void wakeup_dbc(struct qaic_device *qdev, u32 dbc_id);
void release_dbc(struct qaic_device *qdev, u32 dbc_id);

void wake_all_cntl(struct qaic_device *qdev);
void qaic_dev_reset_clean_local_state(struct qaic_device *qdev);
#endif /* QAICINTERNAL_H_ */
