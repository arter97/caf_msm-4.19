// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2019-2020, The Linux Foundation. All rights reserved. */

#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/idr.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <linux/spinlock.h>
#include <linux/srcu.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <uapi/misc/qaic.h>

#include "qaic.h"

#define PGOFF_DBC_SHIFT 32
#define PGOFF_DBC_MASK	GENMASK_ULL(63, 32)
#define SEM_VAL_MASK	GENMASK_ULL(11, 0)
#define SEM_INDEX_MASK	GENMASK_ULL(4, 0)
#define BULK_XFER	BIT(3)
#define GEN_COMPLETION	BIT(4)
#define INBOUND_XFER	1
#define OUTBOUND_XFER	2
#define REQHP_OFF	0x0 /* we read this */
#define REQTP_OFF	0x4 /* we write this */
#define RSPHP_OFF	0x8 /* we write this */
#define RSPTP_OFF	0xc /* we read this */

#define ENCODE_SEM(val, index, sync, cmd, flags)			\
			((val) |					\
			(index) << 16 |					\
			(sync) << 22 |					\
			(cmd) << 24 |					\
			((cmd) ? BIT(31) : 0) |				\
			(((flags) & SEM_INSYNCFENCE) ? BIT(30) : 0) |	\
			(((flags) & SEM_OUTSYNCFENCE) ? BIT(29) : 0))

static unsigned int wait_exec_default_timeout = 5000; /* 5 sec default */
module_param(wait_exec_default_timeout, uint, 0600);

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

struct dbc_rsp { /* everything must be little endian encoded */
	u16	req_id;
	u16	status;
} __packed;

struct mem_handle {
	struct sg_table		*sgt;  /* Mapped pages */
	int			nents; /* num dma mapped elements in sgt */
	int			dir;   /* see enum dma_data_direction */
	struct dbc_req		*reqs;
	struct list_head	list;
	u16			req_id;/* req_id for the xfer while in flight */
	struct completion	xfer_done;
	struct kref		ref_count;
	struct qaic_device	*qdev;
	bool			queued;
	bool			no_xfer;
};

inline int get_dbc_req_elem_size(void)
{
	return sizeof(struct dbc_req);
}

inline int get_dbc_rsp_elem_size(void)
{
	return sizeof(struct dbc_rsp);
}

static int reserve_pages(unsigned long start_pfn, unsigned long nr_pages,
			 bool reserve)
{
	unsigned long pfn;
	unsigned long end_pfn = start_pfn + nr_pages;
	struct page *page;

	for (pfn = start_pfn; pfn < end_pfn; pfn++) {
		if (!pfn_valid(pfn))
			return -EINVAL;
		page =  pfn_to_page(pfn);
		if (reserve)
			SetPageReserved(page);
		else
			ClearPageReserved(page);
	}
	return 0;
}

static int alloc_handle(struct qaic_device *qdev, struct qaic_mem_req *req)
{
	struct mem_handle *mem;
	struct scatterlist *sg;
	struct sg_table *sgt;
	struct page *page;
	int buf_extra;
	int max_order;
	int nr_pages;
	int order;
	int nents;
	int ret;

	if (!(req->dir == DMA_TO_DEVICE || req->dir == DMA_FROM_DEVICE ||
	      req->dir == DMA_BIDIRECTIONAL)) {
		ret = -EINVAL;
		goto out;
	}

	mem = kmalloc(sizeof(*mem), GFP_KERNEL);
	if (!mem) {
		ret = -ENOMEM;
		goto out;
	}

	if (req->size) {
		nr_pages = DIV_ROUND_UP(req->size, PAGE_SIZE);
		/*
		 * calculate how much extra we are going to allocate, to remove
		 * later
		 */
		buf_extra = (PAGE_SIZE - req->size % PAGE_SIZE) % PAGE_SIZE;
		max_order = min(MAX_ORDER, get_order(req->size));
		mem->no_xfer = false;
	} else {
		/* allocate a single page for book keeping */
		nr_pages = 1;
		buf_extra = 0;
		max_order = 0;
		mem->no_xfer = true;
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

		if (reserve_pages(page_to_pfn(page), 1 << order, true))
			goto free_partial_alloc;

		sg_set_page(sg, page, PAGE_SIZE << order, 0);
		sgt->nents++;
		nr_pages -= 1 << order;
		if (!nr_pages) {
			if (buf_extra)
				sg_set_page(sg, page,
					    (PAGE_SIZE << order) - buf_extra,
					    0);
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
	mem->qdev = qdev;
	mem->queued = false;

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

	kref_init(&mem->ref_count);

	return 0;

lock_fail:
	kfree(mem->reqs);
req_alloc_fail:
	dma_unmap_sg(&qdev->pdev->dev, sgt->sgl, sgt->nents, req->dir);
free_partial_alloc:
	for (sg = sgt->sgl; sg; sg = sg_next(sg))
		if (sg_page(sg)) {
			reserve_pages(page_to_pfn(sg_page(sg)),
				      DIV_ROUND_UP(sg->length, PAGE_SIZE),
				      false);
			__free_pages(sg_page(sg), get_order(sg->length));
		}
	sg_free_table(sgt);
free_sgt:
	kfree(sgt);
free_mem:
	kfree(mem);
out:
	return ret;
}

static void free_handle_mem(struct kref *kref)
{
	struct mem_handle *mem = container_of(kref, struct mem_handle,
					      ref_count);
	struct scatterlist *sg;
	struct sg_table *sgt;

	sgt = mem->sgt;
	dma_unmap_sg(&mem->qdev->pdev->dev, sgt->sgl, sgt->nents, mem->dir);
	for (sg = sgt->sgl; sg; sg = sg_next(sg))
		if (sg_page(sg)) {
			reserve_pages(page_to_pfn(sg_page(sg)),
				      DIV_ROUND_UP(sg->length, PAGE_SIZE),
				      false);
			__free_pages(sg_page(sg), get_order(sg->length));
		}
	sg_free_table(sgt);
	kfree(sgt);
	kfree(mem->reqs);
	kfree(mem);
}

static int free_handle(struct qaic_device *qdev, struct qaic_mem_req *req)
{
	struct mem_handle *mem;
	unsigned long flags;
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
	mem = idr_find(&qdev->dbc[dbc_id].mem_handles, handle);
	if (mem) {
		spin_lock_irqsave(&qdev->dbc[dbc_id].xfer_lock, flags);
		if (mem->queued)
			ret = -EINVAL;
		else
			idr_remove(&qdev->dbc[dbc_id].mem_handles, handle);
		spin_unlock_irqrestore(&qdev->dbc[dbc_id].xfer_lock, flags);
	} else {
		ret = -ENODEV;
	}
	mutex_unlock(&qdev->dbc[dbc_id].mem_lock);
	if (ret)
		goto lock_fail;

	kref_put(&mem->ref_count, free_handle_mem);

	ret = 0;

lock_fail:
	return ret;
}

int qaic_mem_ioctl(struct qaic_device *qdev, struct qaic_user *usr,
		   unsigned long arg)
{
	struct qaic_mem_req req;
	int rcu_id;
	int ret;

	if (copy_from_user(&req, (void __user *)arg, sizeof(req))) {
		ret = -EFAULT;
		goto out;
	}

	if (req.dbc_id >= QAIC_NUM_DBC || req.resv) {
		ret = -EINVAL;
		goto out;
	}

	rcu_id = srcu_read_lock(&qdev->dbc[req.dbc_id].ch_lock);
	if (!qdev->dbc[req.dbc_id].usr ||
	    usr->handle != qdev->dbc[req.dbc_id].usr->handle) {
		ret = -EPERM;
		goto release_rcu;
	}

	if (!req.handle) {
		ret = alloc_handle(qdev, &req);
		if (!ret && copy_to_user((void __user *)arg, &req,
					 sizeof(req))) {
			ret = -EFAULT;
			free_handle(qdev, &req);
			goto release_rcu;
		}
	} else {
		ret = free_handle(qdev, &req);
	}

release_rcu:
	srcu_read_unlock(&qdev->dbc[req.dbc_id].ch_lock, rcu_id);
out:
	return ret;
}

int qaic_data_mmap(struct qaic_device *qdev, struct qaic_user *usr,
		   struct vm_area_struct *vma)
{
	unsigned long offset = 0;
	struct mem_handle *mem;
	struct scatterlist *sg;
	int handle;
	int dbc_id;
	int rcu_id;
	int ret;

	dbc_id = (vma->vm_pgoff & PGOFF_DBC_MASK) >> PGOFF_DBC_SHIFT;
	handle = vma->vm_pgoff & ~PGOFF_DBC_MASK;

	if (dbc_id >= QAIC_NUM_DBC) {
		ret = -EINVAL;
		goto out;
	}

	rcu_id = srcu_read_lock(&qdev->dbc[dbc_id].ch_lock);
	if (!qdev->dbc[dbc_id].usr ||
	    usr->handle != qdev->dbc[dbc_id].usr->handle) {
		ret = -EPERM;
		goto release_rcu;
	}

	ret = mutex_lock_interruptible(&qdev->dbc[dbc_id].mem_lock);
	if (ret)
		goto release_rcu;
	mem = idr_find(&qdev->dbc[dbc_id].mem_handles, handle);
	mutex_unlock(&qdev->dbc[dbc_id].mem_lock);
	if (!mem) {
		ret = -ENODEV;
		goto release_rcu;
	}

	if (mem->no_xfer) {
		ret = -EINVAL;
		goto release_rcu;
	}

	for (sg = mem->sgt->sgl; sg; sg = sg_next(sg)) {
		if (sg_page(sg)) {
			ret = remap_pfn_range(vma, vma->vm_start + offset,
					      page_to_pfn(sg_page(sg)),
					      sg->length, vma->vm_page_prot);
			if (ret)
				goto release_rcu;
			offset += sg->length;
		}
	}

release_rcu:
	srcu_read_unlock(&qdev->dbc[dbc_id].ch_lock, rcu_id);
out:
	return ret;
}

static bool invalid_sem(struct qaic_sem *sem)
{
	if (sem->val & ~SEM_VAL_MASK || sem->index & ~SEM_INDEX_MASK ||
	    !(sem->presync == 0 || sem->presync == 1) || sem->resv ||
	    sem->flags & ~(SEM_INSYNCFENCE | SEM_OUTSYNCFENCE) ||
	    sem->cmd > SEM_WAIT_GT_0)
		return true;
	return false;
}

static int encode_execute(struct qaic_device *qdev, struct mem_handle *mem,
			  struct qaic_execute *exec, u16 req_id)
{
	u8 cmd = BULK_XFER;
	u64 db_addr = cpu_to_le64(exec->db_addr);
	u8 db_len;
	u32 db_data = cpu_to_le32(exec->db_data);
	struct scatterlist *sg;
	u64 dev_addr;
	int presync_sem;
	int i;

	if (!mem->no_xfer)
		cmd |= (exec->dir == DMA_TO_DEVICE ? INBOUND_XFER :
								OUTBOUND_XFER);

	req_id = cpu_to_le16(req_id);

	if (exec->db_len && !IS_ALIGNED(exec->db_addr, exec->db_len / 8))
		return -EINVAL;

	presync_sem = exec->sem0.presync + exec->sem1.presync +
		      exec->sem2.presync + exec->sem3.presync;
	if (presync_sem > 1)
		return -EINVAL;

	presync_sem = exec->sem0.presync << 0 | exec->sem1.presync << 1 |
		      exec->sem2.presync << 2 | exec->sem3.presync << 3;

	switch (exec->db_len) {
	case 32:
		db_len = BIT(7);
		break;
	case 16:
		db_len = BIT(7) | 1;
		break;
	case 8:
		db_len = BIT(7) | 2;
		break;
	case 0:
		db_len = 0; /* doorbell is not active for this command */
		break;
	default:
		return -EINVAL; /* should never hit this */
	}

	/*
	 * When we end up splitting up a single request (ie a mem handle) into
	 * multiple DMA requests, we have to manage the sync data carefully.
	 * There can only be one presync sem.  That needs to be on every xfer
	 * so that the DMA engine doesn't transfer data before the receiver is
	 * ready.  We only do the doorbell and postsync sems after the xfer.
	 * To guarantee previous xfers for the request are complete, we use a
	 * fence.
	 */
	dev_addr = exec->dev_addr;
	for_each_sg(mem->sgt->sgl, sg, mem->nents, i) {
		mem->reqs[i].req_id = req_id;
		mem->reqs[i].cmd = cmd;
		mem->reqs[i].src_addr =
			cpu_to_le64(exec->dir == DMA_TO_DEVICE ?
					sg_dma_address(sg) : dev_addr);
		mem->reqs[i].dest_addr =
			cpu_to_le64(exec->dir == DMA_TO_DEVICE ?
					dev_addr : sg_dma_address(sg));
		mem->reqs[i].len = cpu_to_le32(sg_dma_len(sg));
		switch (presync_sem) {
		case BIT(0):
			mem->reqs[i].sem_cmd0 = cpu_to_le32(
						ENCODE_SEM(exec->sem0.val,
							exec->sem0.index,
							exec->sem0.presync,
							exec->sem0.cmd,
							exec->sem0.flags));
			break;
		case BIT(1):
			mem->reqs[i].sem_cmd1 = cpu_to_le32(
						ENCODE_SEM(exec->sem1.val,
							exec->sem1.index,
							exec->sem1.presync,
							exec->sem1.cmd,
							exec->sem1.flags));
			break;
		case BIT(2):
			mem->reqs[i].sem_cmd2 = cpu_to_le32(
						ENCODE_SEM(exec->sem2.val,
							exec->sem2.index,
							exec->sem2.presync,
							exec->sem2.cmd,
							exec->sem2.flags));
			break;
		case BIT(3):
			mem->reqs[i].sem_cmd3 = cpu_to_le32(
						ENCODE_SEM(exec->sem3.val,
							exec->sem3.index,
							exec->sem3.presync,
							exec->sem3.cmd,
							exec->sem3.flags));
			break;
		}
		dev_addr += sg_dma_len(sg);
	}
	/* add post transfer stuff to last segment */
	i--;
	mem->reqs[i].cmd |= GEN_COMPLETION;
	mem->reqs[i].db_addr = db_addr;
	mem->reqs[i].db_len = db_len;
	mem->reqs[i].db_data = db_data;
	exec->sem0.flags |= (exec->dir == DMA_TO_DEVICE ? SEM_INSYNCFENCE :
							SEM_OUTSYNCFENCE);
	mem->reqs[i].sem_cmd0 = cpu_to_le32(ENCODE_SEM(exec->sem0.val,
						       exec->sem0.index,
						       exec->sem0.presync,
						       exec->sem0.cmd,
						       exec->sem0.flags));
	mem->reqs[i].sem_cmd1 = cpu_to_le32(ENCODE_SEM(exec->sem1.val,
						       exec->sem1.index,
						       exec->sem1.presync,
						       exec->sem1.cmd,
						       exec->sem1.flags));
	mem->reqs[i].sem_cmd2 = cpu_to_le32(ENCODE_SEM(exec->sem2.val,
						       exec->sem2.index,
						       exec->sem2.presync,
						       exec->sem2.cmd,
						       exec->sem2.flags));
	mem->reqs[i].sem_cmd3 = cpu_to_le32(ENCODE_SEM(exec->sem3.val,
						       exec->sem3.index,
						       exec->sem3.presync,
						       exec->sem3.cmd,
						       exec->sem3.flags));

	return 0;
}

static int commit_execute(struct qaic_device *qdev, struct mem_handle *mem,
			  u32 dbc_id)
{
	struct dma_bridge_chan *dbc = &qdev->dbc[dbc_id];
	u32 head = le32_to_cpu(__raw_readl(dbc->dbc_base + REQHP_OFF));
	u32 tail = le32_to_cpu(__raw_readl(dbc->dbc_base + REQTP_OFF));
	u32 avail = head - tail;
	struct dbc_req *reqs = mem->reqs;
	bool two_copy = tail + mem->nents > dbc->nelem;

	if (head == U32_MAX || tail == U32_MAX)
		/* PCI link error */
		return -ENODEV;

	if (head <= tail)
		avail += dbc->nelem;

	--avail;

	if (avail < mem->nents)
		return -EAGAIN;

	if (two_copy) {
		avail = dbc->nelem - tail;
		avail = min_t(u32, avail, mem->nents);
		memcpy(dbc->req_q_base + tail * get_dbc_req_elem_size(),
		       reqs, sizeof(*reqs) * avail);
		reqs += avail;
		avail = mem->nents - avail;
		if (avail)
			memcpy(dbc->req_q_base, reqs, sizeof(*reqs) * avail);
	} else {
		memcpy(dbc->req_q_base + tail * get_dbc_req_elem_size(),
		       reqs, sizeof(*reqs) * mem->nents);
	}

	init_completion(&mem->xfer_done);
	list_add_tail(&mem->list, &dbc->xfer_list);
	tail = (tail + mem->nents) % dbc->nelem;
	__raw_writel(cpu_to_le32(tail), dbc->dbc_base + REQTP_OFF);
	return 0;
}

int qaic_execute_ioctl(struct qaic_device *qdev, struct qaic_user *usr,
		       unsigned long arg)
{
	struct mem_handle *mem;
	struct qaic_execute *exec;
	unsigned long flags;
	bool queued;
	u16 req_id;
	int handle;
	int dbc_id;
	int rcu_id;
	int ret;

	exec = kmalloc(sizeof(*exec), GFP_KERNEL);
	if (!exec) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(exec, (void __user *)arg, sizeof(*exec))) {
		ret = -EFAULT;
		goto free_exec;
	}

	if (exec->dbc_id > QAIC_NUM_DBC || exec->ver != 1 ||
	    !(exec->dir == 1 || exec->dir == 2) ||
	    !(exec->db_len == 32 || exec->db_len == 16 || exec->db_len == 8 ||
	      exec->db_len == 0) ||
	    invalid_sem(&exec->sem0) || invalid_sem(&exec->sem1) ||
	    invalid_sem(&exec->sem2) || invalid_sem(&exec->sem3) ||
	    exec->resv) {
		ret = -EINVAL;
		goto free_exec;
	}

	rcu_id = srcu_read_lock(&qdev->dbc[exec->dbc_id].ch_lock);
	if (!qdev->dbc[exec->dbc_id].usr ||
	    qdev->dbc[exec->dbc_id].usr->handle != usr->handle) {
		ret = -EPERM;
		goto release_rcu;
	}

	handle = exec->handle & ~PGOFF_DBC_MASK;
	dbc_id = (exec->handle & PGOFF_DBC_MASK) >> PGOFF_DBC_SHIFT;

	/* we shifted up by PAGE_SHIFT to make mmap happy, need to undo that */
	handle >>= PAGE_SHIFT;
	dbc_id >>= PAGE_SHIFT;

	if (dbc_id != exec->dbc_id) {
		ret = -EINVAL;
		goto release_rcu;
	}

	ret = mutex_lock_interruptible(&qdev->dbc[exec->dbc_id].mem_lock);
	if (ret)
		goto release_rcu;
	mem = idr_find(&qdev->dbc[exec->dbc_id].mem_handles, handle);
	if (!mem) {
		ret = -ENODEV;
		mutex_unlock(&qdev->dbc[exec->dbc_id].mem_lock);
		goto release_rcu;
	}
	/* prevent free_handle from taking the memory from under us */
	kref_get(&mem->ref_count);
	mutex_unlock(&qdev->dbc[exec->dbc_id].mem_lock);

	if (mem->dir != DMA_BIDIRECTIONAL && mem->dir != exec->dir) {
		ret = -EINVAL;
		kref_put(&mem->ref_count, free_handle_mem);
		goto release_rcu;
	}

	spin_lock_irqsave(&qdev->dbc[exec->dbc_id].xfer_lock, flags);
	req_id = qdev->dbc[exec->dbc_id].next_req_id++;
	queued = mem->queued;
	mem->queued = true;
	spin_unlock_irqrestore(&qdev->dbc[exec->dbc_id].xfer_lock, flags);
	mem->req_id = req_id;

	if (queued) {
		ret = -EINVAL;
		kref_put(&mem->ref_count, free_handle_mem);
		goto release_rcu;
	}

	ret = encode_execute(qdev, mem, exec, req_id);
	if (ret) {
		mem->queued = false;
		kref_put(&mem->ref_count, free_handle_mem);
		goto release_rcu;
	}

	dma_sync_sg_for_device(&qdev->pdev->dev, mem->sgt->sgl, mem->sgt->nents,
			       mem->dir);

	spin_lock_irqsave(&qdev->dbc[exec->dbc_id].xfer_lock, flags);
	ret = commit_execute(qdev, mem, exec->dbc_id);
	spin_unlock_irqrestore(&qdev->dbc[exec->dbc_id].xfer_lock, flags);
	if (ret) {
		mem->queued = false;
		kref_put(&mem->ref_count, free_handle_mem);
		goto sync_to_cpu;
	}

	goto release_rcu;

sync_to_cpu:
	dma_sync_sg_for_cpu(&qdev->pdev->dev, mem->sgt->sgl, mem->sgt->nents,
			    mem->dir);
release_rcu:
	srcu_read_unlock(&qdev->dbc[exec->dbc_id].ch_lock, rcu_id);
free_exec:
	kfree(exec);
out:
	return ret;
}

irqreturn_t dbc_irq_handler(int irq, void *data)
{
	struct dma_bridge_chan *dbc = data;
	struct qaic_device *qdev = dbc->qdev;
	struct mem_handle *mem;
	struct mem_handle *i;
	struct dbc_rsp *rsp;
	unsigned long flags;
	int rcu_id;
	u16 status;
	u16 req_id;
	u32 head;
	u32 tail;

	rcu_id = srcu_read_lock(&dbc->ch_lock);
read_fifo:
	/*
	 * if this channel isn't assigned or gets unassigned during processing
	 * we have nothing further to do
	 */
	if (!dbc->usr) {
		srcu_read_unlock(&dbc->ch_lock, rcu_id);
		return IRQ_HANDLED;
	}

	head = le32_to_cpu(__raw_readl(dbc->dbc_base + RSPHP_OFF));
	tail = le32_to_cpu(__raw_readl(dbc->dbc_base + RSPTP_OFF));

	if (head == U32_MAX || tail == U32_MAX) {
		/* PCI link error */
		srcu_read_unlock(&dbc->ch_lock, rcu_id);
		return IRQ_HANDLED;
	}

	if (head == tail) { /* queue empty */
		srcu_read_unlock(&dbc->ch_lock, rcu_id);
		return IRQ_HANDLED;
	}

	while (head != tail) {
		rsp = dbc->rsp_q_base + head * sizeof(*rsp);
		req_id = le16_to_cpu(rsp->req_id);
		status = le16_to_cpu(rsp->status);
		if (status)
			pci_dbg(qdev->pdev, "req_id %d failed with status %d\n",
				req_id, status);
		spin_lock_irqsave(&dbc->xfer_lock, flags);
		list_for_each_entry_safe(mem, i, &dbc->xfer_list, list) {
			if (mem->req_id == req_id) {
				list_del(&mem->list);
				dma_sync_sg_for_cpu(&qdev->pdev->dev,
						    mem->sgt->sgl,
						    mem->sgt->nents,
						    mem->dir);
				mem->queued = false;
				complete_all(&mem->xfer_done);
				kref_put(&mem->ref_count, free_handle_mem);
				break;
			}
		}
		spin_unlock_irqrestore(&dbc->xfer_lock, flags);
		head = (head + 1) % dbc->nelem;
		__raw_writel(cpu_to_le32(head), dbc->dbc_base + RSPHP_OFF);
	}

	/* elements might have been put in the queue while we were processing */
	goto read_fifo;
}

int qaic_wait_exec_ioctl(struct qaic_device *qdev, struct qaic_user *usr,
			 unsigned long arg)
{
	struct mem_handle *mem;
	struct qaic_wait_exec *wait;
	unsigned int timeout;
	int handle;
	int dbc_id;
	int rcu_id;
	int ret;

	wait = kmalloc(sizeof(*wait), GFP_KERNEL);
	if (!wait) {
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(wait, (void __user *)arg, sizeof(*wait))) {
		ret = -EFAULT;
		goto free_wait;
	}

	if (wait->resv) {
		ret = -EINVAL;
		goto free_wait;
	}

	handle = wait->handle & ~PGOFF_DBC_MASK;
	dbc_id = (wait->handle & PGOFF_DBC_MASK) >> PGOFF_DBC_SHIFT;

	/* we shifted up by PAGE_SHIFT to make mmap happy, need to undo that */
	handle >>= PAGE_SHIFT;
	dbc_id >>= PAGE_SHIFT;

	if (dbc_id > QAIC_NUM_DBC) {
		ret = -EINVAL;
		goto free_wait;
	}

	rcu_id = srcu_read_lock(&qdev->dbc[dbc_id].ch_lock);
	if (!qdev->dbc[dbc_id].usr ||
	    qdev->dbc[dbc_id].usr->handle != usr->handle) {
		ret = -EPERM;
		goto release_rcu;
	}

	ret = mutex_lock_interruptible(&qdev->dbc[dbc_id].mem_lock);
	if (ret)
		goto release_rcu;
	mem = idr_find(&qdev->dbc[dbc_id].mem_handles, handle);
	mutex_unlock(&qdev->dbc[dbc_id].mem_lock);
	if (!mem) {
		ret = -ENODEV;
		goto release_rcu;
	}

	/* we don't want the mem handle freed under us in case of deactivate */
	kref_get(&mem->ref_count);
	srcu_read_unlock(&qdev->dbc[dbc_id].ch_lock, rcu_id);
	timeout = wait->timeout ? wait->timeout : wait_exec_default_timeout;
	ret = wait_for_completion_interruptible_timeout(&mem->xfer_done,
				msecs_to_jiffies(timeout));
	rcu_id = srcu_read_lock(&qdev->dbc[dbc_id].ch_lock);
	if (!ret)
		ret = -ETIMEDOUT;
	else if (ret > 0)
		ret = 0;
	if (!qdev->dbc[dbc_id].usr) {
		ret = -EPERM;
		goto release_rcu;
	}

	kref_put(&mem->ref_count, free_handle_mem);

release_rcu:
	srcu_read_unlock(&qdev->dbc[dbc_id].ch_lock, rcu_id);
free_wait:
	kfree(wait);
out:
	return ret;
}

int disable_dbc(struct qaic_device *qdev, u32 dbc_id, struct qaic_user *usr)
{
	if (!qdev->dbc[dbc_id].usr ||
	    qdev->dbc[dbc_id].usr->handle != usr->handle)
		return -EPERM;

	qdev->dbc[dbc_id].usr = NULL;
	synchronize_srcu(&qdev->dbc[dbc_id].ch_lock);
	return 0;
}

void wakeup_dbc(struct qaic_device *qdev, u32 dbc_id)
{
	struct mem_handle *mem;
	struct mem_handle *i;

	qdev->dbc[dbc_id].usr = NULL;
	synchronize_srcu(&qdev->dbc[dbc_id].ch_lock);
	list_for_each_entry_safe(mem, i, &qdev->dbc[dbc_id].xfer_list, list) {
		list_del(&mem->list);
		dma_sync_sg_for_cpu(&qdev->pdev->dev,
				    mem->sgt->sgl,
				    mem->sgt->nents,
				    mem->dir);
		complete_all(&mem->xfer_done);
	}
}

void release_dbc(struct qaic_device *qdev, u32 dbc_id)
{
	struct mem_handle *mem;
	int next_id = 0;

	wakeup_dbc(qdev, dbc_id);

	dma_free_coherent(&qdev->pdev->dev, qdev->dbc[dbc_id].total_size,
			  qdev->dbc[dbc_id].req_q_base,
			  qdev->dbc[dbc_id].dma_addr);
	qdev->dbc[dbc_id].total_size = 0;
	qdev->dbc[dbc_id].req_q_base = NULL;
	qdev->dbc[dbc_id].dma_addr = 0;
	qdev->dbc[dbc_id].nelem = 0;
	qdev->dbc[dbc_id].usr = NULL;
	while (1) {
		mem = idr_get_next(&qdev->dbc[dbc_id].mem_handles, &next_id);
		if (!mem)
			break;
		idr_remove(&qdev->dbc[dbc_id].mem_handles, next_id);
		/* account for the missing put from the irq handler */
		if (mem->queued) {
			mem->queued = false;
			kref_put(&mem->ref_count, free_handle_mem);
		}
		kref_put(&mem->ref_count, free_handle_mem);
	}
	qdev->dbc[dbc_id].in_use = false;
	wake_up(&qdev->dbc[dbc_id].dbc_release);
}

void qaic_data_get_fifo_info(struct dma_bridge_chan *dbc, u32 *head, u32 *tail)
{
	if (!dbc || !head || !tail)
		return;

	*head = le32_to_cpu(__raw_readl(dbc->dbc_base + REQHP_OFF));
	*tail = le32_to_cpu(__raw_readl(dbc->dbc_base + REQTP_OFF));
}
