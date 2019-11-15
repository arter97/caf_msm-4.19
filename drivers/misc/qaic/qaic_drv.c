// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2019, The Linux Foundation. All rights reserved. */

#include <linux/delay.h>
#include <linux/module.h>
#include <linux/pci.h>

#include "mhi_controller.h"

#define PCI_VENDOR_ID_QTI		0x17cb

#define PCI_DEV_AIC100			0xa100

struct qaic_device {
	struct pci_dev		*pdev;
	int 			bars;
	void __iomem		*bar_0;
	struct mhi_controller 	*mhi_cntl;
};

static int qaic_pci_probe(struct pci_dev *pdev,
			  const struct pci_device_id *id)
{
	int ret;
	int mhi_irq;
	struct qaic_device *qdev;

	pci_dbg(pdev, "%s\n", __func__);

	qdev = kmalloc(sizeof(*qdev), GFP_KERNEL);
	if (!qdev) {
		ret = -ENOMEM;
		goto qdev_fail;
	}

	pci_set_drvdata(pdev, qdev);

	qdev->bars = pci_select_bars(pdev, IORESOURCE_MEM);

	/* make sure the device has the expected BARs */
	if (qdev->bars != (BIT(0) | BIT(2) | BIT(4))) {
		pci_dbg(pdev, "%s: expected BARs 0, 2, and 4 not found in device.  Found 0x%x\n", __func__, qdev->bars);
		ret = -EINVAL;
		goto bar_fail;
	}

	ret = pci_enable_device(pdev);
	if (ret)
		goto enable_fail;

	ret = pci_request_selected_regions(pdev, qdev->bars, "aic100");
	if (ret)
		goto request_regions_fail;

	pci_set_master(pdev);

	ret = pci_set_dma_mask(pdev, DMA_BIT_MASK(64));
	if (ret)
		goto dma_mask_fail;
	ret = pci_set_consistent_dma_mask(pdev, DMA_BIT_MASK(64));
	if (ret)
		goto dma_mask_fail;

	qdev->bar_0 = pci_ioremap_bar(pdev, 0);
	if (!qdev->bar_0) {
		ret = -ENOMEM;
		goto ioremap_0_fail;
	}

	ret = pci_alloc_irq_vectors(pdev, 1, 32, PCI_IRQ_MSI);
	if (ret < 0)
		goto alloc_irq_fail;

	if (ret < 32)
		pci_warn(pdev, "%s: Requested 32 MSIs.  Obtained %d MSIs which is less than ideal and may impact performance.\n", __func__, ret);

	mhi_irq = pci_irq_vector(pdev, 0);
	if (mhi_irq < 0) {
		ret = mhi_irq;
		goto get_mhi_irq_fail;
	}

	qdev->mhi_cntl = qaic_mhi_register_controller(pdev, qdev->bar_0, mhi_irq);
	if (IS_ERR(qdev->mhi_cntl)) {
		ret = PTR_ERR(qdev->mhi_cntl);
		goto mhi_register_fail;
	}

	pci_dbg(pdev, "%s: successful init\n", __func__);
	return 0;

mhi_register_fail:
get_mhi_irq_fail:
	pci_free_irq_vectors(pdev);
alloc_irq_fail:
	iounmap(qdev->bar_0);
ioremap_0_fail:
dma_mask_fail:
	pci_clear_master(pdev);
	pci_release_selected_regions(pdev, qdev->bars);
request_regions_fail:
	pci_disable_device(pdev);
enable_fail:
	pci_set_drvdata(pdev, NULL);
bar_fail:
	kfree(qdev);
qdev_fail:
	return ret;
}

static void qaic_pci_remove(struct pci_dev *pdev)
{
	struct qaic_device *qdev = pci_get_drvdata(pdev);

	if (!qdev)
		return;

	qaic_mhi_free_controller(qdev->mhi_cntl);
	pci_free_irq_vectors(pdev);
	iounmap(qdev->bar_0);
	pci_clear_master(pdev);
	pci_release_selected_regions(pdev, qdev->bars);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(qdev);
}

static const struct pci_device_id ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_QTI, PCI_DEV_AIC100), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, ids);

static struct pci_driver qaic_pci_driver = {
	.name = "QTI Cloud AI",
	.id_table = ids,
	.probe = qaic_pci_probe,
	.remove = qaic_pci_remove,
};

static int __init qaic_init(void)
{
	return pci_register_driver(&qaic_pci_driver);
}

static void __exit qaic_exit(void)
{
	pci_unregister_driver(&qaic_pci_driver);
}

module_init(qaic_init);
module_exit(qaic_exit);

MODULE_DESCRIPTION("QTI Cloud AI Accelerators Driver");
MODULE_LICENSE("GPL v2");
