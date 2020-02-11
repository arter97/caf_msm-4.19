/* SPDX-License-Identifier: GPL-2.0-only */

/* Copyright (c) 2020, The Linux Foundation. All rights reserved. */

#ifndef __QAIC_DEBUGFS_H__
#define __QAIC_DEBUGFS_H__

#include <linux/debugfs.h>
#include <linux/pci.h>

#define QAIC_DEBUGFS_ROOT			"qaic"
#define QAIC_DEBUGFS_DBC_PREFIX		"dbc"
#define QAIC_DEBUGFS_DBC_FIFO_SIZE	"fifo_size"
#define QAIC_DEBUGFS_DBC_QUEUED		"queued"

extern struct dentry *qaic_debugfs_dir;

#ifdef CONFIG_DEBUG_FS

void qaic_debugfs_init(void);
void qaic_debugfs_exit(void);
int qaic_debugfs_add_pci_device(struct pci_dev *pdev);
void qaic_debugfs_remove_pci_device(struct pci_dev *pdev);

#else /* !CONFIG_DEBUG_FS */

void qaic_debugfs_init(void) {}
void qaic_debugfs_exit(void) {}
int qaic_debugfs_add_pci_device(struct pci_dev *pdev)
{
	return -ENOENT;
}
void qaic_debugfs_remove_pci_device(struct pci_dev *pdev) {}

#endif /* !CONFIG_DEBUG_FS */
#endif /* __QAIC_DEBUGFS_H__ */
