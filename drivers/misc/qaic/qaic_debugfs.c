// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2020, The Linux Foundation. All rights reserved. */

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/pci.h>
#include <linux/types.h>

#include "qaic.h"
#include "qaic_debugfs.h"


struct dentry *qaic_debugfs_dir;

static int read_dbc_fifo_size(void *data, u64 *value)
{
	struct dma_bridge_chan *dbc = (struct dma_bridge_chan *) data;

	*value = dbc->nelem;
	return 0;
}

static int read_dbc_queued(void *data, u64 *value)
{
	struct dma_bridge_chan *dbc = (struct dma_bridge_chan *) data;
	u32 tail, head;

	qaic_data_get_fifo_info(dbc, &head, &tail);

	if (head == U32_MAX || tail == U32_MAX)
		*value = 0;
	else if (head > tail)
		*value = dbc->nelem - head + tail;
	else
		*value = tail - head;

	return 0;
}

DEFINE_SIMPLE_ATTRIBUTE(dbc_fifo_size_fops, read_dbc_fifo_size, NULL, "%llu\n");
DEFINE_SIMPLE_ATTRIBUTE(dbc_queued_fops, read_dbc_queued, NULL, "%llu\n");

static void qaic_debugfs_add_dbc_entry(struct pci_dev *pdev, uint16_t dbc_id,
				       struct dentry *parent)
{
	char name[16];
	struct qaic_device *qdev = pci_get_drvdata(pdev);
	struct dma_bridge_chan *dbc = &qdev->dbc[dbc_id];

	snprintf(name, 16, "%s%03u", QAIC_DEBUGFS_DBC_PREFIX, dbc_id);

	dbc->debugfs_root = debugfs_create_dir(name, parent);

	debugfs_create_file(QAIC_DEBUGFS_DBC_FIFO_SIZE, 0444, dbc->debugfs_root,
						dbc, &dbc_fifo_size_fops);

	debugfs_create_file(QAIC_DEBUGFS_DBC_QUEUED, 0444, dbc->debugfs_root,
						dbc, &dbc_queued_fops);
}

void qaic_debugfs_remove_pci_device(struct pci_dev *pdev)
{
	struct qaic_device *qdev = pci_get_drvdata(pdev);

	debugfs_remove_recursive(qdev->debugfs_root);
}

int qaic_debugfs_add_pci_device(struct pci_dev *pdev)
{
	struct pci_bus *bus = pdev->bus;
	struct qaic_device *qdev = pci_get_drvdata(pdev);
	char name[16];
	uint16_t i;

	if (qaic_debugfs_dir == NULL) {
		pci_dbg(pdev, "Qaic debugfs root not preset\n");
		return -ENOENT;
	}

	snprintf(name, 16, "%04x:%02x.%02x.%x", pci_domain_nr(bus),
		 bus->number, PCI_SLOT(pdev->devfn),
		 PCI_FUNC(pdev->devfn));

	qdev->debugfs_root = debugfs_create_dir(name, qaic_debugfs_dir);

	for (i = 0; i < QAIC_NUM_DBC; ++i)
		qaic_debugfs_add_dbc_entry(pdev, i, qdev->debugfs_root);

	return 0;
}

void qaic_debugfs_init(void)
{
	if (qaic_debugfs_dir != NULL)
		return;

	qaic_debugfs_dir = debugfs_create_dir("qaic", NULL);
}

void qaic_debugfs_exit(void)
{
	debugfs_remove_recursive(qaic_debugfs_dir);
}

