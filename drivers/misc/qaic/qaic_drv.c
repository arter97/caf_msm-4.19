// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2019, The Linux Foundation. All rights reserved. */

#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/idr.h>
#include <linux/list.h>
#include <linux/mhi.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <uapi/misc/qaic.h>

#include "mhi_controller.h"
#include "qaic.h"

#define PCI_VENDOR_ID_QTI		0x17cb

#define PCI_DEV_AIC100			0xa100

#define QAIC_NAME			"QTI Cloud AI"
#define QAIC_MAX_MINORS			256

static int qaic_major;
static struct class *qaic_class;
static DEFINE_IDR(qaic_devs);
static DEFINE_MUTEX(qaic_devs_lock);

static int qaic_device_open(struct inode *inode, struct file *filp);
static int qaic_device_release(struct inode *inode, struct file *filp);
static long qaic_ioctl(struct file *filp, unsigned int cmd, unsigned long arg);
static int qaic_mmap(struct file *filp, struct vm_area_struct *vma);

static const struct file_operations qaic_ops = {
	.owner = THIS_MODULE,
	.open = qaic_device_open,
	.release = qaic_device_release,
	.unlocked_ioctl = qaic_ioctl,
	.compat_ioctl = qaic_ioctl,
	.mmap = qaic_mmap,
};

static int qaic_device_open(struct inode *inode, struct file *filp)
{
	struct qaic_device *qdev;
	struct qaic_user *usr;
	int ret;

	ret = mutex_lock_interruptible(&qaic_devs_lock);
	if (ret)
		return ret;
	qdev = idr_find(&qaic_devs, iminor(inode));
	mutex_unlock(&qaic_devs_lock);

	pci_dbg(qdev->pdev, "%s pid:%d\n", __func__, current->pid);

	usr = kmalloc(sizeof(*usr), GFP_KERNEL);
	if (!usr)
		return -ENOMEM;

	usr->handle = current->pid;
	usr->qdev = qdev;
	filp->private_data = usr;

	nonseekable_open(inode, filp);

	return 0;
}

static int qaic_device_release(struct inode *inode, struct file *filp)
{
	struct qaic_user *usr = filp->private_data;
	struct qaic_device *qdev = usr->qdev;

	pci_dbg(qdev->pdev, "%s pid:%d\n", __func__, current->pid);

	qaic_release_usr(qdev, usr);

	filp->private_data = NULL;
	kfree(usr);
	return 0;
}

static long qaic_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	struct qaic_user *usr = filp->private_data;
	struct qaic_device *qdev = usr->qdev;
	unsigned int nr = _IOC_NR(cmd);
	int ret;

	pci_dbg(qdev->pdev, "%s pid:%d cmd:0x%x (%c nr=%d len=%d dir=%d)\n",
		__func__, current->pid, cmd, _IOC_TYPE(cmd), _IOC_NR(cmd),
		_IOC_SIZE(cmd), _IOC_DIR(cmd));

	if (_IOC_TYPE(cmd) != 'Q')
		return -ENOTTY;

	switch (nr) {
	case QAIC_IOCTL_MANAGE_NR:
		if (_IOC_DIR(cmd) != (_IOC_READ | _IOC_WRITE) ||
		    _IOC_SIZE(cmd) != sizeof(struct manage_msg)) {
			ret = -EINVAL;
			break;
		}
		ret = qaic_manage_ioctl(qdev, usr, arg);
		break;
	case QAIC_IOCTL_MEM_NR:
		if (_IOC_DIR(cmd) != (_IOC_READ | _IOC_WRITE) ||
		    _IOC_SIZE(cmd) != sizeof(struct mem_req)) {
			ret = -EINVAL;
			break;
		}
		ret = qaic_mem_ioctl(qdev, usr, arg);
		break;
	case QAIC_IOCTL_EXECUTE_NR:
		if (_IOC_DIR(cmd) != _IOC_WRITE ||
		    _IOC_SIZE(cmd) != sizeof(struct execute)) {
			ret = -EINVAL;
			break;
		}
		ret = qaic_execute_ioctl(qdev, usr, arg);
		break;
	case QAIC_IOCTL_WAIT_EXEC_NR:
		if (_IOC_DIR(cmd) != _IOC_WRITE ||
		    _IOC_SIZE(cmd) != sizeof(struct wait_exec)) {
			ret = -EINVAL;
			break;
		}
		ret = qaic_wait_exec_ioctl(qdev, usr, arg);
		break;
	default:
		return -ENOTTY;
	}

	return ret;
}

static int qaic_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct qaic_user *usr = filp->private_data;
	struct qaic_device *qdev = usr->qdev;

	return qaic_data_mmap(qdev, usr, vma);
}

static int qaic_mhi_probe(struct mhi_device *mhi_dev,
			  const struct mhi_device_id *id)
{
	struct qaic_device *qdev;
	dev_t devno;
	int ret;

	/*
	 * Invoking this function indicates that the control channel to the
	 * device is available.  We use that as a signal to indicate that
	 * the device side firmware has booted.  The device side firmware
	 * manages the device resources, so we need to communicate with it
	 * via the control channel in order to utilize the device.  Therefore
	 * we wait until this signal to create the char dev that userspace will
	 * use to control the device, because without the device side firmware,
	 * userspace can't do anything useful.
	 */

	qdev = (struct qaic_device *)pci_get_drvdata(
					to_pci_dev(mhi_dev->mhi_cntrl->dev));

	pci_dbg(qdev->pdev, "%s\n", __func__);

	mhi_device_set_devdata(mhi_dev, qdev);
	qdev->cntl_ch = mhi_dev;

	ret = qaic_control_open(qdev);
	if (ret) {
		pci_dbg(qdev->pdev, "%s: control_open failed %d\n", __func__, ret);
		goto err;
	}

	mutex_lock(&qaic_devs_lock);
	ret = idr_alloc(&qaic_devs, qdev, 0, QAIC_MAX_MINORS, GFP_KERNEL);
	mutex_unlock(&qaic_devs_lock);

	if (ret < 0) {
		pci_dbg(qdev->pdev, "%s: idr_alloc failed %d\n", __func__, ret);
		goto close_control;
	}

	devno = MKDEV(qaic_major, ret);

	cdev_init(&qdev->cdev, &qaic_ops);
	qdev->cdev.owner = THIS_MODULE;
	ret = cdev_add(&qdev->cdev, devno, 1);
	if (ret) {
		pci_dbg(qdev->pdev, "%s: cdev_add failed %d\n", __func__, ret);
		goto free_idr;
	}

	qdev->dev = device_create(qaic_class, NULL, devno, NULL,
				  "qaic_aic100_%04x:%02x:%02x.%d",
				  pci_domain_nr(qdev->pdev->bus),
				  qdev->pdev->bus->number,
				  PCI_SLOT(qdev->pdev->devfn),
				  PCI_FUNC(qdev->pdev->devfn));
	if (IS_ERR(qdev->dev)) {
		ret = PTR_ERR(qdev->dev);
		pci_dbg(qdev->pdev, "%s: device_create failed %d\n", __func__, ret);
		goto free_cdev;
	}

	dev_set_drvdata(qdev->dev, qdev);

	return 0;

free_cdev:
	cdev_del(&qdev->cdev);
free_idr:
	mutex_lock(&qaic_devs_lock);
	idr_remove(&qaic_devs, MINOR(devno));
	mutex_unlock(&qaic_devs_lock);
close_control:
	qaic_control_close(qdev);
err:
	return ret;
}

static void qaic_mhi_remove(struct mhi_device *mhi_dev)
{
	struct qaic_device *qdev;
	dev_t devno;

	/* invoked when a MHI error is detected, or MHI power down */

	qdev = mhi_device_get_devdata(mhi_dev);

	pci_dbg(qdev->pdev, "%s\n", __func__);

	devno = qdev->dev->devt;
	qdev->dev = NULL;
	device_destroy(qaic_class, devno);
	cdev_del(&qdev->cdev);
	mutex_lock(&qaic_devs_lock);
	idr_remove(&qaic_devs, MINOR(devno));
	mutex_unlock(&qaic_devs_lock);
}

static void reset_work_func(struct work_struct *work)
{
	struct qaic_device *qdev;
	int ret;

	qdev = container_of(work, struct qaic_device, reset_work);

	ret = pci_reset_function(qdev->pdev);
	if (ret < 0)
		pci_err(qdev->pdev, "Failed to reset device from device signal\n");
}

static irqreturn_t reset_irq_handler(int irq, void *data)
{
	struct qaic_device *qdev = data;

	schedule_work(&qdev->reset_work);

	return IRQ_HANDLED;
}

static int qaic_pci_probe(struct pci_dev *pdev,
			  const struct pci_device_id *id)
{
	int ret;
	int i;
	int mhi_irq;
	struct qaic_device *qdev;

	pci_dbg(pdev, "%s\n", __func__);

	qdev = kzalloc(sizeof(*qdev), GFP_KERNEL);
	if (!qdev) {
		ret = -ENOMEM;
		goto qdev_fail;
	}

	pci_set_drvdata(pdev, qdev);
	qdev->pdev = pdev;
	mutex_init(&qdev->cntl_mutex);
	INIT_LIST_HEAD(&qdev->cntl_xfer_list);
	INIT_WORK(&qdev->reset_work, reset_work_func);
	for (i = 0; i < QAIC_NUM_DBC; ++i) {
		mutex_init(&qdev->dbc[i].mem_lock);
		spin_lock_init(&qdev->dbc[i].xfer_lock);
		idr_init(&qdev->dbc[i].mem_handles);
		qdev->dbc[i].qdev = qdev;
		qdev->dbc[i].id = i;
		INIT_LIST_HEAD(&qdev->dbc[i].xfer_list);
		init_srcu_struct(&qdev->dbc[i].ch_lock);
	}

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

	qdev->bar_2 = pci_ioremap_bar(pdev, 2);
	if (!qdev->bar_2) {
		ret = -ENOMEM;
		goto ioremap_2_fail;
	}

	for (i = 0; i < QAIC_NUM_DBC; ++i)
		qdev->dbc[i].dbc_base = qdev->bar_2 + QAIC_DBC_OFF(i);

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

	for (i = 0; i < QAIC_NUM_DBC; ++i) {
		ret = devm_request_irq(&pdev->dev, pci_irq_vector(pdev, i + 1),
				       dbc_irq_handler, IRQF_SHARED, "qaic_dbc",
				       &qdev->dbc[i]);
		if (ret)
			goto get_dbc_irq_failed;
	}

	ret = devm_request_irq(&pdev->dev, pci_irq_vector(pdev, 31),
			       reset_irq_handler, 0, "qaic_reset", qdev);
	if (ret)
		goto get_reset_irq_failed;

	qdev->mhi_cntl = qaic_mhi_register_controller(pdev, qdev->bar_0, mhi_irq);
	if (IS_ERR(qdev->mhi_cntl)) {
		ret = PTR_ERR(qdev->mhi_cntl);
		goto mhi_register_fail;
	}

	pci_dbg(pdev, "%s: successful init\n", __func__);
	return 0;

mhi_register_fail:
	devm_free_irq(&pdev->dev, pci_irq_vector(pdev, 31), qdev);
get_reset_irq_failed:
get_dbc_irq_failed:
	for (i = 0; i < QAIC_NUM_DBC; ++i)
		devm_free_irq(&pdev->dev, pci_irq_vector(pdev, i + 1),
			      &qdev->dbc[i]);
get_mhi_irq_fail:
	pci_free_irq_vectors(pdev);
alloc_irq_fail:
	iounmap(qdev->bar_2);
ioremap_2_fail:
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
	for (i = 0; i < QAIC_NUM_DBC; ++i)
		cleanup_srcu_struct(&qdev->dbc[i].ch_lock);
	kfree(qdev);
qdev_fail:
	return ret;
}

static void qaic_pci_remove(struct pci_dev *pdev)
{
	struct qaic_device *qdev = pci_get_drvdata(pdev);
	int i;

	pci_dbg(pdev, "%s\n", __func__);
	if (!qdev)
		return;

	qaic_mhi_free_controller(qdev->mhi_cntl);
	for (i = 0; i < QAIC_NUM_DBC; ++i) {
		devm_free_irq(&pdev->dev, pci_irq_vector(pdev, i + 1),
			      &qdev->dbc[i]);
		cleanup_srcu_struct(&qdev->dbc[i].ch_lock);
	}
	devm_free_irq(&pdev->dev, pci_irq_vector(pdev, 31), qdev);
	pci_free_irq_vectors(pdev);
	iounmap(qdev->bar_0);
	pci_clear_master(pdev);
	pci_release_selected_regions(pdev, qdev->bars);
	pci_disable_device(pdev);
	pci_set_drvdata(pdev, NULL);
	kfree(qdev);
}

static const struct mhi_device_id qaic_mhi_match_table[] = {
        { .chan = "QAIC_CONTROL", },
        {},
};

static struct mhi_driver qaic_mhi_driver = {
	.id_table = qaic_mhi_match_table,
	.remove = qaic_mhi_remove,
	.probe = qaic_mhi_probe,
	.ul_xfer_cb = qaic_mhi_ul_xfer_cb,
	.dl_xfer_cb = qaic_mhi_dl_xfer_cb,
	.driver = {
		.name = "qaic_mhi",
		.owner = THIS_MODULE,
	},
};

static const struct pci_device_id ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_QTI, PCI_DEV_AIC100), },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, ids);

static struct pci_driver qaic_pci_driver = {
	.name = QAIC_NAME,
	.id_table = ids,
	.probe = qaic_pci_probe,
	.remove = qaic_pci_remove,
};

static int __init qaic_init(void)
{
	int ret;
	dev_t dev;

	pr_debug("qaic: init\n");
	ret = alloc_chrdev_region(&dev, 0, QAIC_MAX_MINORS, QAIC_NAME);
	if (ret < 0) {
		pr_debug("qaic: alloc_chrdev_region failed %d\n", ret);
		goto out;
	}

	qaic_major = MAJOR(dev);

	qaic_class = class_create(THIS_MODULE, QAIC_NAME);
	if (IS_ERR(qaic_class)) {
		ret = PTR_ERR(qaic_class);
		pr_debug("qaic: class_create failed %d\n", ret);
		goto free_major;
	}

	ret = mhi_driver_register(&qaic_mhi_driver);
	if (ret) {
		pr_debug("qaic: mhi_driver_register failed %d\n", ret);
		goto free_class;
	}

	ret = pci_register_driver(&qaic_pci_driver);

	if (ret) {
		pr_debug("qaic: pci_register_driver failed %d\n", ret);
		goto free_mhi;
	}

	pr_debug("qaic: init success\n");
	goto out;

free_mhi:
	mhi_driver_unregister(&qaic_mhi_driver);
free_class:
	class_destroy(qaic_class);
free_major:
	unregister_chrdev_region(MKDEV(qaic_major, 0), QAIC_MAX_MINORS);
out:
	return ret;
}

static void __exit qaic_exit(void)
{
	pr_debug("qaic: exit\n");
	pci_unregister_driver(&qaic_pci_driver);
	mhi_driver_unregister(&qaic_mhi_driver);
	class_destroy(qaic_class);
	unregister_chrdev_region(MKDEV(qaic_major, 0), QAIC_MAX_MINORS);
	idr_destroy(&qaic_devs);
}

module_init(qaic_init);
module_exit(qaic_exit);

MODULE_DESCRIPTION("QTI Cloud AI Accelerators Driver");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.2.0"); /* MAJOR.MINOR.PATCH */
