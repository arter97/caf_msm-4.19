// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2019, The Linux Foundation. All rights reserved. */

#include <linux/dma-mapping.h>
#include <linux/idr.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <uapi/misc/qaic.h>

#include "qaic.h"

#define PGOFF_DBC_SHIFT 32
#define PGOFF_DBC_MASK	GENMASK_ULL(63, 32)

struct dbc_req { /* everything must be little endian encoded */
	u16	req_id;
	u8	seq_id;
	u8	cmd;
	u32	resv;
	u64	src_addr;
	u64	dest_addr;
	u32	len;
	u32	resv2;
	u64	db_addr; /* doorbell address */
	u8	db_len; /* not a raw value, special encoding */
	u8	resv3;
	u16	resv4;
	u32	db_data;
	u32	sem_cmd0;
	u32	sem_cmd1;
	u32	sem_cmd2;
	u32	sem_cmd3;
} __packed;

struct mem_handle {
	struct sg_table	*sgt;  /* Mapped pages */
	int		nents; /* number of dma mapped elements in sgt */
	int		dir;   /* DMA_BIDIRECTIONAL/TO_DEVICE/FROM_DEVICE */
	struct dbc_req	*reqs;
};

static int alloc_handle(struct qaic_device *qdev, struct mem_req *req)
{
	struct mem_handle *mem;
	struct scatterlist *sg;
	struct sg_table *sgt;
	struct page *page;
	int max_order;
	int nr_pages;
	int order;
	int nents;
	int ret;

	if (!req->size ||
	    !(req->dir == DMA_TO_DEVICE || req->dir == DMA_FROM_DEVICE ||
	      req->dir == DMA_BIDIRECTIONAL)) {
		ret = -EINVAL;
		goto out;
	}

	nr_pages = DIV_ROUND_UP(req->size, PAGE_SIZE);

	mem = kmalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem) {
		ret = -ENOMEM;
		goto out;
	}

	sgt = kmalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt) {
		ret = -ENOMEM;
		goto free_mem;
	}

	if (sg_alloc_table(sgt, nr_pages, GFP_KERNEL)) {
		ret = -ENOMEM;
		goto free_sgt;
	}

	sg = sgt->sgl;
	sgt->nents = 0;
	max_order = min(MAX_ORDER, get_order(req->size));

	/*
	 * Try to allocate enough pages to cover the request.  High order pages
	 * will be contiguous, which will be conducive to DMA.
	 */
	while (1) {
		order = min(fls(nr_pages) - 1, max_order);
		while (1) {
			page = alloc_pages(GFP_KERNEL | GFP_HIGHUSER |
					   __GFP_NOWARN | __GFP_ZERO |
					   (order ? __GFP_NORETRY :
							__GFP_RETRY_MAYFAIL),
					   order);
			if (page)
				break;
			if (!order--) {
				sg_set_page(sg, NULL, 0, 0);
				sg_mark_end(sg);
				ret = -ENOMEM;
				goto free_partial_alloc;
			}
			max_order = order;
		}

		sg_set_page(sg, page, PAGE_SIZE << order, 0);
		sgt->nents++;
		nr_pages -= 1 << order;
		if (!nr_pages) {
			sg_mark_end(sg);
			break;
		}
		sg = sg_next(sg);
	}

	nents = dma_map_sg(&qdev->pdev->dev, sgt->sgl, sgt->nents, req->dir);
	if (!nents) {
		ret = -EFAULT;
		goto free_partial_alloc;
	}

	if (req->dir == DMA_TO_DEVICE || req->dir == DMA_BIDIRECTIONAL)
		dma_sync_sg_for_cpu(&qdev->pdev->dev, sgt->sgl, sgt->nents,
				    req->dir);

	mem->reqs = kcalloc(nents, sizeof(*mem->reqs), GFP_KERNEL);
	if (!mem->reqs) {
		ret = -ENOMEM;
		goto req_alloc_fail;
	}

	mem->sgt = sgt;
	mem->nents = nents;
	mem->dir = req->dir;

	ret = mutex_lock_interruptible(&qdev->dbc[req->dbc_id].mem_lock);
	if (ret)
		goto lock_fail;
	ret = idr_alloc(&qdev->dbc[req->dbc_id].mem_handles, mem, 1, 0,
		       GFP_KERNEL);
	mutex_unlock(&qdev->dbc[req->dbc_id].mem_lock);
	if (ret < 0)
		goto lock_fail;

	req->handle = ret | (u64)req->dbc_id << PGOFF_DBC_SHIFT;
	/*
	 * When userspace uses the handle as the offset parameter to mmap,
	 * it needs to be in multiples of PAGE_SIZE.
	 */
	req->handle <<= PAGE_SHIFT;

	return 0;

lock_fail:
	kfree(mem->reqs);
req_alloc_fail:
	dma_unmap_sg(&qdev->pdev->dev, sgt->sgl, sgt->nents, req->dir);
free_partial_alloc:
	for (sg = sgt->sgl; sg; sg = sg_next(sg))
		if (sg_page(sg))
			__free_pages(sg_page(sg), get_order(sg->length));
free_sgt:
	kfree(sgt);
free_mem:
	kfree(mem);
out:
	return ret;
}

static int free_handle(struct qaic_device *qdev, struct mem_req *req)
{
	struct mem_handle *mem;
	struct scatterlist *sg;
	struct sg_table *sgt;
	int handle;
	int dbc_id;
	int ret;

	handle = req->handle & ~PGOFF_DBC_MASK;
	dbc_id = (req->handle & PGOFF_DBC_MASK) >> PGOFF_DBC_SHIFT;

	/* we shifted up by PAGE_SHIFT to make mmap happy, need to undo that */
	handle >>= PAGE_SHIFT;
	dbc_id >>= PAGE_SHIFT;

	if (dbc_id != req->dbc_id)
		return -EINVAL;

	ret = mutex_lock_interruptible(&qdev->dbc[dbc_id].mem_lock);
	if (ret)
		goto lock_fail;
	mem = idr_remove(&qdev->dbc[dbc_id].mem_handles, handle);
	mutex_unlock(&qdev->dbc[dbc_id].mem_lock);
	if (!mem) {
		ret = -ENODEV;
		goto lock_fail;
	}

	sgt = mem->sgt;
	dma_unmap_sg(&qdev->pdev->dev, sgt->sgl, sgt->nents, mem->dir);
	for (sg = sgt->sgl; sg; sg = sg_next(sg))
		if (sg_page(sg))
			__free_pages(sg_page(sg), get_order(sg->length));
	kfree(sgt);
	kfree(mem->reqs);
	kfree(mem);

	ret = 0;

lock_fail:
	return ret;
}

int qaic_mem_ioctl(struct qaic_device *qdev, struct qaic_user *usr,
		   unsigned long arg)
{
	struct mem_req req;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
		ret = -EFAULT;
		goto out;
	}

	if (req.dbc_id >= QAIC_NUM_DBC || req.resv) {
		ret = -EINVAL;
		goto out;
	}

	if (!qdev->dbc[req.dbc_id].usr ||
	    usr->handle != qdev->dbc[req.dbc_id].usr->handle) {
		ret = -EPERM;
		goto out;
	}

	if (!req.handle) {
		ret = alloc_handle(qdev, &req);
		if (!ret && copy_to_user((void __user *)arg, &req,
					 sizeof(req))) {
			ret = -EFAULT;
			free_handle(qdev, &req);
			goto out;
		}
	} else {
		ret = free_handle(qdev, &req);
	}

out:
	return ret;
}
