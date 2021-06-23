// SPDX-License-Identifier: GPL-2.0-only
/* driver/misc/qrc/qrc_core.c
 *
 * Copyright (c) 2021, The Linux Foundation. All rights reserved.
 */

#include <linux/errno.h>
#include <linux/time.h>
#include <linux/firmware.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <asm/dma-iommu.h>
#include <linux/msm_dma_iommu_mapping.h>

#define UPD_PCI_F4  0xF4

#define UPD_PCI_F4_FWDOWNLOADENABLE  (0x0001)
#define UPD_PCI_F4_FWDOWNLOADLOCK    (0x0002)
#define UPD_PCI_F4_SETDATA0          (0x0100)
#define UPD_PCI_F4_SETDATA1          (0x0200)
#define UPD_PCI_F4_RESULT            (0x0070)

#define UPD_PCI_F8  0xF8

#define UPD_PCI_FC  0xFC

enum SET_DATA {
	SET_DATA_PAGE0,
	SET_DATA_PAGE1
};

#define SMMU_BASE 0x10000000
#define SMMU_SIZE 0x40000000

struct firmware *fw_pointer;

static int upd720x_download_enable(struct pci_dev *pDev)
{
	unsigned int read_data;
	int result;

	result = pci_read_config_dword(pDev, UPD_PCI_F4, &read_data);
	pr_info("Set FW Download enable\n");
	result = pci_write_config_dword(pDev, UPD_PCI_F4, read_data |
		UPD_PCI_F4_FWDOWNLOADENABLE);
	return result;
}

static int upd720x_download_lock(struct pci_dev *pDev)
{
	unsigned int read_data;
	int result;

	result = pci_read_config_dword(pDev, UPD_PCI_F4, &read_data);
	pr_info("Set FW Download lock\n");
	result = pci_write_config_dword(pDev, UPD_PCI_F4, read_data |
		UPD_PCI_F4_FWDOWNLOADLOCK);
	return result;
}

static int upd720x_set_data0(struct pci_dev *pDev)
{
	unsigned int read_data;
	int result;

	result = pci_read_config_dword(pDev, UPD_PCI_F4, &read_data);
	result = pci_write_config_dword(pDev, UPD_PCI_F4,
		(read_data & ~UPD_PCI_F4_SETDATA1) |
		UPD_PCI_F4_SETDATA0);

	return result;
}

static int upd720x_set_data1(struct pci_dev *pDev)
{
	unsigned int read_data;
	int result;

	result = pci_read_config_dword(pDev, UPD_PCI_F4, &read_data);
	result = pci_write_config_dword(pDev, UPD_PCI_F4,
		(read_data & ~UPD_PCI_F4_SETDATA0) |
		UPD_PCI_F4_SETDATA1);

	return result;
}

static int upd720x_download_clearcontrol(struct pci_dev *pDev)
{
	int read_buf;
	int rc;

	rc = pci_read_config_dword(pDev, UPD_PCI_F4, &read_buf);
	if (rc == 0) {
		rc = pci_write_config_dword(pDev, UPD_PCI_F4, read_buf &
		~UPD_PCI_F4_FWDOWNLOADENABLE);
	}
	return rc;
}
int upd720x_firmware_download(struct pci_dev  *pDev,
	unsigned char *pFWImage, unsigned int firmware_size)
{
	enum SET_DATA page = SET_DATA_PAGE0;
	int offset;
	unsigned int *image = (unsigned int *)pFWImage;
	unsigned int fw_dwordsize   = firmware_size /
		(sizeof(unsigned int) / sizeof(unsigned char));

	if ((firmware_size %
	(sizeof(unsigned int) / sizeof(unsigned char))) != 0)
		fw_dwordsize++;

	if (upd720x_download_enable(pDev) == -EFAULT) {
		pr_info("Set FW Download Enable is timeout\n");
		return -EFAULT;
	}

	for (offset = 0; offset < fw_dwordsize; offset++) {
		switch (page) {
		case SET_DATA_PAGE0:
			pci_write_config_dword(pDev, UPD_PCI_F8, image[offset]);

			if (upd720x_set_data0(pDev) == -EFAULT)
				return -EFAULT;
			page = SET_DATA_PAGE1;
			break;

		case SET_DATA_PAGE1:
			pci_write_config_dword(pDev, UPD_PCI_FC, image[offset]);
			if (upd720x_set_data1(pDev) == -EFAULT)
				return -EFAULT;
			page = SET_DATA_PAGE0;
			break;
		default:
			break;
		}
	}

	if (upd720x_download_clearcontrol(pDev) == -EFAULT)
		return -EFAULT;

	if (upd720x_download_lock(pDev) == -EFAULT)
		return -EFAULT;

	return 0;
}

static void upd720x_firmware_cb(const struct firmware *cfg, void *data)
{

	int result;

	if (!cfg) {
		pr_err("upd720 get firmware failed\n");
		return;
	}

	result = upd720x_firmware_download(data,
				(unsigned char *)cfg->data, cfg->size);
	if (result)
		pr_err("upd720x download firmware failed\n");

	release_firmware(cfg);
}

int upd720x_finish_download(struct pci_dev *pDev)
{
	int ret;

	//no waitting load firmware
	ret = request_firmware_nowait(THIS_MODULE, true,
			"K2026090.mem", &pDev->bus->dev, GFP_KERNEL, pDev,
			upd720x_firmware_cb);

	return ret;
}
