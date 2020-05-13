// SPDX-License-Identifier: GPL-2.0-only

/* Copyright (c) 2019-2020, The Linux Foundation. All rights reserved. */

#include <asm/byteorder.h>
#include <linux/completion.h>
#include <linux/dma-mapping.h>
#include <linux/kref.h>
#include <linux/list.h>
#include <linux/mhi.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/pci.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <linux/uaccess.h>
#include <linux/workqueue.h>
#include <linux/wait.h>
#include <uapi/misc/qaic.h>

#include "qaic.h"
#include "qaic_trace.h"

#define MANAGE_MAGIC_NUMBER	0x43494151 /* "QAIC" in little endian */
#define QAIC_DBC_Q_GAP		0x100
#define QAIC_DBC_Q_BUF_ALIGN	0x1000
#define RESP_TIMEOUT		60 * HZ

/*
 * wire encoding structures for the manage protocol.
 * All fields are little endian on the wire
 */
struct _msg_hdr {
	u32 magic_number;
	u32 sequence_number;
	u32 len; /* length of this message */
	u32 count; /* number of transactions in this message */
	u32 handle; /* unique id to track the resources consumed */
} __packed;

struct _msg {
	struct _msg_hdr hdr;
	u8 data[QAIC_MANAGE_MAX_MSG_LENGTH];
} __packed;

struct wrapper_msg {
	struct kref ref_count;
	struct _msg msg;
};

struct _trans_hdr {
	u32 type;
	u32 len;
} __packed;

struct _trans_passthrough {
	struct _trans_hdr hdr;
	u8 data[0];
} __packed;

struct _addr_size_pair {
	u64 addr;
	u64 size;
} __packed;

struct _trans_dma_xfer {
	struct _trans_hdr hdr;
	u32 tag;
	u32 count;
	struct _addr_size_pair data[0];
} __packed;

struct _trans_activate_to_dev {
	struct _trans_hdr hdr;
	u32 buf_len;
	u64 req_q_addr;
	u32 req_q_size;
	u64 rsp_q_addr;
	u32 rsp_q_size;
	u32 reserved;
} __packed;

struct _trans_activate_from_dev {
	struct _trans_hdr hdr;
	u32 status;
	u32 dbc_id;
} __packed;

struct _trans_deactivate_from_dev {
	struct _trans_hdr hdr;
	u32 status;
	u32 dbc_id;
} __packed;

struct _trans_terminate_to_dev {
	struct _trans_hdr hdr;
	u32 handle;
} __packed;

struct _trans_terminate_from_dev {
	struct _trans_hdr hdr;
	u32 status;
} __packed;

struct _trans_status_to_dev {
	struct _trans_hdr hdr;
} __packed;

struct _trans_status_from_dev {
	struct _trans_hdr hdr;
	u16 major;
	u16 minor;
	u32 status;
} __packed;

struct xfer_queue_elem {
	struct list_head list;
	u32 seq_num;
	struct completion xfer_done;
	void *buf;
};

struct dma_xfer {
	struct list_head list;
	struct sg_table *sgt;
	struct page **page_list;
	unsigned long nr_pages;
};

struct ioctl_resources {
	struct list_head dma_xfers;
	void *buf;
	dma_addr_t dma_addr;
	u32 total_size;
	u32 nelem;
	void *rsp_q_base;
	u32 status;
	u32 dbc_id;
};

struct resp_work {
	struct work_struct work;
	struct qaic_device *qdev;
	void *buf;
};

static void free_wrapper(struct kref *ref)
{
	struct wrapper_msg *wrapper = container_of(ref, struct wrapper_msg,
						   ref_count);

	kfree(wrapper);
}

static void save_dbc_buf(struct qaic_device *qdev,
			 struct ioctl_resources *resources,
			 struct qaic_user *usr)
{
	u32 dbc_id = resources->dbc_id;

	if (resources->buf) {
		wait_event_interruptible(qdev->dbc[dbc_id].dbc_release,
					 !qdev->dbc[dbc_id].in_use);
		qdev->dbc[dbc_id].req_q_base = resources->buf;
		qdev->dbc[dbc_id].rsp_q_base = resources->rsp_q_base;
		qdev->dbc[dbc_id].dma_addr = resources->dma_addr;
		qdev->dbc[dbc_id].total_size = resources->total_size;
		qdev->dbc[dbc_id].nelem = resources->nelem;
		qdev->dbc[dbc_id].usr = usr;
		qdev->dbc[dbc_id].in_use = true;
		resources->buf = 0;
	}
}

static void free_dbc_buf(struct qaic_device *qdev,
			 struct ioctl_resources *resources)
{
	if (resources->buf)
		dma_free_coherent(&qdev->pdev->dev, resources->total_size,
				  resources->buf, resources->dma_addr);
	resources->buf = 0;
}

static void free_dma_xfers(struct qaic_device *qdev,
			   struct ioctl_resources *resources)
{
	struct dma_xfer *xfer;
	struct dma_xfer *x;
	int i;

	list_for_each_entry_safe(xfer, x, &resources->dma_xfers, list) {
		dma_unmap_sg(&qdev->pdev->dev, xfer->sgt->sgl, xfer->sgt->nents,
			     DMA_TO_DEVICE);
		sg_free_table(xfer->sgt);
		kfree(xfer->sgt);
		for (i = 0; i < xfer->nr_pages; ++i)
			put_page(xfer->page_list[i]);
		kfree(xfer->page_list);
		list_del(&xfer->list);
		kfree(xfer);
	}
}

static int encode_passthrough(struct qaic_device *qdev, void *trans,
			      struct _msg *msg, u32 *user_len)
{
	struct qaic_manage_trans_passthrough *in_trans = trans;
	struct _trans_passthrough *out_trans = (void *)msg + msg->hdr.len;

	if (msg->hdr.len + in_trans->hdr.len > sizeof(*msg)) {
		trace_encode_error(qdev, "passthrough trans exceeds msg len");
		return -ENOSPC;
	}

	memcpy(out_trans, in_trans, in_trans->hdr.len);
	msg->hdr.len += in_trans->hdr.len;
	*user_len += in_trans->hdr.len;
	out_trans->hdr.type = cpu_to_le32(TRANS_PASSTHROUGH_TO_DEV);
	out_trans->hdr.len = cpu_to_le32(out_trans->hdr.len);

	return 0;
}

static int encode_dma(struct qaic_device *qdev, void *trans, struct _msg *msg,
		      u32 *user_len, struct ioctl_resources *resources)
{
	struct qaic_manage_trans_dma_xfer *in_trans = trans;
	struct _trans_dma_xfer *out_trans = (void *)msg + msg->hdr.len;
	struct dma_xfer *xfer;
	unsigned long nr_pages;
	struct page **page_list;
	struct scatterlist *last;
	struct scatterlist *sg;
	struct sg_table *sgt;
	unsigned int dma_len;
	int nents;
	int dmas;
	int ret;
	int i;

	if (in_trans->addr + in_trans->size < in_trans->addr ||
	    !in_trans->size) {
		trace_encode_error(qdev, "dma trans addr range overflow or no size");
		ret = -EINVAL;
		goto out;
	}

	xfer = kmalloc(sizeof(*xfer), GFP_KERNEL);
	if (!xfer) {
		trace_encode_error(qdev, "dma no mem for xfer");
		ret = -ENOMEM;
		goto out;
	}

	nr_pages = PAGE_ALIGN(in_trans->size + offset_in_page(in_trans->addr))
								>> PAGE_SHIFT;

	page_list = kmalloc_array(nr_pages, sizeof(*page_list), GFP_KERNEL);
	if (!page_list) {
		trace_encode_error(qdev, "dma page list alloc fail");
		ret = -ENOMEM;
		goto free_resource;
	}

	ret = get_user_pages_fast(in_trans->addr, nr_pages, 0, page_list);
	if (ret < 0 || ret != nr_pages) {
		trace_encode_error(qdev, "dma get user pages fail");
		ret = -EFAULT;
		goto free_page_list;
	}

	sgt = kmalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt) {
		trace_encode_error(qdev, "dma sgt alloc fail");
		ret = -ENOMEM;
		goto put_pages;
	}

	ret = sg_alloc_table_from_pages(sgt, page_list, nr_pages,
					offset_in_page(in_trans->addr),
					in_trans->size, GFP_KERNEL);
	if (ret) {
		trace_encode_error(qdev, "dma alloc table from pages fail");
		ret = -ENOMEM;
		goto free_sgt;
	}

	nents = dma_map_sg(&qdev->pdev->dev, sgt->sgl, sgt->nents,
			   DMA_TO_DEVICE);
	if (!nents) {
		trace_encode_error(qdev, "dma mapping failed");
		ret = -EFAULT;
		goto free_table;
	}

	/*
	 * It turns out several of the iommu drivers don't combine adjacent
	 * regions, which is really what we expect based on the description of
	 * dma_map_sg(), so lets see if that can be done.  It makes our message
	 * more efficent.
	 */
	dmas = 0;
	last = sgt->sgl;
	for_each_sg(sgt->sgl, sg, nents, i) {
		if (sg_dma_address(last) + sg_dma_len(last) !=
		    sg_dma_address(sg))
			dmas++;
		last = sg;
	}

	/*
	 * now that we finally know how many memory segments we will be encoding
	 * we can check to see if we have space in the message
	 */
	if (msg->hdr.len + sizeof(*out_trans) + dmas * sizeof(*out_trans->data)
							> sizeof(*msg)) {
		trace_encode_error(qdev, "dma trans exceeds msg len");
		ret = -ENOSPC;
		goto dma_unmap;
	}

	msg->hdr.len += sizeof(*out_trans) + dmas * sizeof(*out_trans->data);

	out_trans->hdr.type = cpu_to_le32(TRANS_DMA_XFER_TO_DEV);
	out_trans->hdr.len = cpu_to_le32(sizeof(*out_trans) +
					 dmas * sizeof(*out_trans->data));
	out_trans->tag = cpu_to_le32(in_trans->tag);
	out_trans->count = cpu_to_le32(dmas);

	i = 0;
	last = sgt->sgl;
	dma_len = 0;
	for_each_sg(sgt->sgl, sg, nents, dmas) {
		/* hit a discontinuity, finalize segment and start new one */
		if (sg_dma_address(last) + sg_dma_len(last) !=
		    sg_dma_address(sg)) {
			out_trans->data[i].size = cpu_to_le64(dma_len);
			if (dma_len)
				i++;
			dma_len = 0;
			out_trans->data[i].addr =
						cpu_to_le64(sg_dma_address(sg));
		}
		dma_len += sg_dma_len(sg);
		last = sg;
	}
	/* finalize the last segment */
	out_trans->data[i].size = cpu_to_le64(dma_len);

	*user_len += in_trans->hdr.len;

	xfer->sgt = sgt;
	xfer->page_list = page_list;
	xfer->nr_pages = nr_pages;
	list_add(&xfer->list, &resources->dma_xfers);
	return 0;

dma_unmap:
	dma_unmap_sg(&qdev->pdev->dev, sgt->sgl, sgt->nents, DMA_TO_DEVICE);
free_table:
	sg_free_table(sgt);
free_sgt:
	kfree(sgt);
put_pages:
	for (i = 0; i < nr_pages; ++i)
		put_page(page_list[i]);
free_page_list:
	kfree(page_list);
free_resource:
	kfree(xfer);
out:
	return ret;
}

static int encode_activate(struct qaic_device *qdev, void *trans,
			   struct _msg *msg, u32 *user_len,
			   struct ioctl_resources *resources)
{
	struct qaic_manage_trans_activate_to_dev *in_trans = trans;
	struct _trans_activate_to_dev *out_trans = (void *)msg + msg->hdr.len;
	dma_addr_t dma_addr;
	void *buf;
	u32 nelem;
	u32 size;

	if (msg->hdr.len + sizeof(*out_trans) > sizeof(*msg)) {
		trace_encode_error(qdev, "activate trans exceeds msg len");
		return -ENOSPC;
	}

	if (!in_trans->queue_size) {
		trace_encode_error(qdev, "activate unspecified queue size");
		return -EINVAL;
	}

	if (in_trans->resv) {
		trace_encode_error(qdev, "activate non-zero resv");
		return -EINVAL;
	}

	nelem = in_trans->queue_size;
	size = (get_dbc_req_elem_size() + get_dbc_rsp_elem_size()) * nelem;
	if (size / nelem != get_dbc_req_elem_size() + get_dbc_rsp_elem_size()) {
		trace_encode_error(qdev, "activate queue size overflow");
		return -EINVAL;
	}

	if (size + QAIC_DBC_Q_GAP + QAIC_DBC_Q_BUF_ALIGN < size) {
		trace_encode_error(qdev, "activate queue size align overflow");
		return -EINVAL;
	}

	size = ALIGN((size + QAIC_DBC_Q_GAP), QAIC_DBC_Q_BUF_ALIGN);

	buf = dma_alloc_coherent(&qdev->pdev->dev, size, &dma_addr, GFP_KERNEL);
	if (!buf) {
		trace_encode_error(qdev, "activate queue alloc fail");
		return -ENOMEM;
	}

	out_trans->hdr.type = cpu_to_le32(TRANS_ACTIVATE_TO_DEV);
	out_trans->hdr.len = cpu_to_le32(sizeof(*out_trans));
	out_trans->buf_len = cpu_to_le32(size);
	out_trans->req_q_addr = cpu_to_le64(dma_addr);
	out_trans->req_q_size = cpu_to_le32(nelem);
	out_trans->rsp_q_addr = cpu_to_le64(dma_addr + size - nelem *
							get_dbc_rsp_elem_size());
	out_trans->rsp_q_size = cpu_to_le32(nelem);

	*user_len += in_trans->hdr.len;
	msg->hdr.len += sizeof(*out_trans);

	resources->buf = buf;
	resources->dma_addr = dma_addr;
	resources->total_size = size;
	resources->nelem = nelem;
	resources->rsp_q_base = buf + size - nelem * get_dbc_rsp_elem_size();
	return 0;
}

static int encode_deactivate(struct qaic_device *qdev, void *trans,
			     u32 *user_len, struct qaic_user *usr)
{
	struct qaic_manage_trans_deactivate *in_trans = trans;

	if (in_trans->dbc_id >= QAIC_NUM_DBC || in_trans->resv) {
		trace_encode_error(qdev, "deactivate invalid dbc id or resv not zero");
		return -EINVAL;
	}

	*user_len += in_trans->hdr.len;

	return disable_dbc(qdev, in_trans->dbc_id, usr);
}

static int encode_status(struct qaic_device *qdev, void *trans,
			 struct _msg *msg, u32 *user_len)
{
	struct qaic_manage_trans_status_to_dev *in_trans = trans;
	struct _trans_status_to_dev *out_trans = (void *)msg + msg->hdr.len;

	if (msg->hdr.len + in_trans->hdr.len > sizeof(*msg)) {
		trace_encode_error(qdev, "status trans exceeds msg len");
		return -ENOSPC;
	}

	out_trans->hdr.type = cpu_to_le32(TRANS_STATUS_TO_DEV);
	out_trans->hdr.len = cpu_to_le32(in_trans->hdr.len);
	msg->hdr.len += in_trans->hdr.len;
	*user_len += in_trans->hdr.len;

	return 0;
}
static int encode_message(struct qaic_device *qdev,
			  struct qaic_manage_msg *user_msg, struct _msg *msg,
			  struct ioctl_resources *resources,
			  struct qaic_user *usr)
{
	struct qaic_manage_trans_hdr *trans_hdr;
	u32 user_len = 0;
	int ret;
	int i;

	msg->hdr.len = sizeof(msg->hdr);
	for (i = 0; i < user_msg->count; ++i) {
		if (user_len >= user_msg->len) {
			trace_encode_error(qdev, "msg exceeds len");
			ret = -EINVAL;
			break;
		}
		trans_hdr = (struct qaic_manage_trans_hdr *)
						(user_msg->data + user_len);
		if (user_len + trans_hdr->len > user_msg->len) {
			trace_encode_error(qdev, "trans exceeds msg len");
			ret = -EINVAL;
			break;
		}

		switch (trans_hdr->type) {
		case TRANS_PASSTHROUGH_FROM_USR:
			ret = encode_passthrough(qdev, trans_hdr, msg,
						 &user_len);
			break;
		case TRANS_DMA_XFER_FROM_USR:
			ret = encode_dma(qdev, trans_hdr, msg, &user_len,
					 resources);
			break;
		case TRANS_ACTIVATE_FROM_USR:
			ret = encode_activate(qdev, trans_hdr, msg, &user_len,
					      resources);
			break;
		case TRANS_DEACTIVATE_FROM_USR:
			ret = encode_deactivate(qdev, trans_hdr, &user_len,
						usr);
			break;
		case TRANS_STATUS_FROM_USR:
			ret = encode_status(qdev, trans_hdr, msg, &user_len);
			break;
		default:
			trace_encode_error(qdev, "unknown trans");
			ret = -EINVAL;
			break;
		}

		if (ret)
			break;
	}

	if (user_len != user_msg->len) {
		trace_encode_error(qdev, "msg processed exceeds len");
		ret = -EINVAL;
	}

	if (ret) {
		free_dma_xfers(qdev, resources);
		free_dbc_buf(qdev, resources);
		return ret;
	}

	msg->hdr.count = user_msg->count;
	return 0;
}

static int decode_passthrough(struct qaic_device *qdev, void *trans,
			      struct qaic_manage_msg *user_msg, u32 *msg_len)
{
	struct _trans_passthrough *in_trans = trans;
	struct qaic_manage_trans_passthrough *out_trans;
	u32 len;

	out_trans = (void *)user_msg->data + user_msg->len;

	len = le32_to_cpu(in_trans->hdr.len);
	if (user_msg->len + len > QAIC_MANAGE_MAX_MSG_LENGTH) {
		trace_decode_error(qdev, "passthrough trans exceeds msg len");
		return -ENOSPC;
	}

	memcpy(out_trans, in_trans, len);
	user_msg->len += len;
	*msg_len += len;
	out_trans->hdr.type = le32_to_cpu(out_trans->hdr.type);
	return 0;
}

static int decode_activate(struct qaic_device *qdev, void *trans,
			   struct qaic_manage_msg *user_msg, u32 *msg_len,
			   struct ioctl_resources *resources,
			   struct qaic_user *usr)
{
	struct _trans_activate_from_dev *in_trans = trans;
	struct qaic_manage_trans_activate_from_dev *out_trans;
	u32 len;

	out_trans = (void *)user_msg->data + user_msg->len;

	len = le32_to_cpu(in_trans->hdr.len);
	if (user_msg->len + len > QAIC_MANAGE_MAX_MSG_LENGTH) {
		trace_decode_error(qdev, "activate trans exceeds msg len");
		return -ENOSPC;
	}

	user_msg->len += len;
	*msg_len += len;
	out_trans->hdr.type = le32_to_cpu(in_trans->hdr.type);
	out_trans->hdr.len = len;
	out_trans->status = le32_to_cpu(in_trans->status);
	out_trans->dbc_id = le32_to_cpu(in_trans->dbc_id);

	if (!resources->buf) {
		trace_decode_error(qdev, "activate with no assigned resources");
		/* how did we get an activate response with a request? */
		return -EINVAL;
	}

	if (out_trans->dbc_id >= QAIC_NUM_DBC) {
		trace_decode_error(qdev, "activate invalid dbc id");
		/*
		 * The device assigned an invalid resource, which should never
		 * happen.  Inject an error so the user can try to recover.
		 */
		out_trans->status = -ENODEV;
	}

	resources->status = out_trans->status;
	resources->dbc_id = out_trans->dbc_id;
	if (!resources->status)
		save_dbc_buf(qdev, resources, usr);
	return 0;
}

static int decode_deactivate(struct qaic_device *qdev, void *trans,
			     u32 *msg_len)
{
	struct _trans_deactivate_from_dev *in_trans = trans;
	u32 dbc_id = le32_to_cpu(in_trans->dbc_id);
	u32 status = le32_to_cpu(in_trans->status);

	if (dbc_id >= QAIC_NUM_DBC) {
		trace_decode_error(qdev, "deactivate invalid dbc id");
		/*
		 * The device assigned an invalid resource, which should never
		 * happen.  Inject an error so the user can try to recover.
		 */
		return -ENODEV;
	}
	if (status) {
		trace_decode_error(qdev, "deactivate device failed");
		/*
		 * Releasing resources failed on the device side, which puts
		 * us in a bind since they may still be in use, so be safe and
		 * do nothing.
		 */
		return -ENODEV;
	}

	release_dbc(qdev, dbc_id);
	*msg_len += sizeof(*in_trans);
	return 0;
}

static int decode_status(struct qaic_device *qdev, void *trans,
			 struct qaic_manage_msg *user_msg, u32 *user_len)
{
	struct _trans_status_from_dev *in_trans = trans;
	struct qaic_manage_trans_status_from_dev *out_trans;
	u32 len;

	out_trans = (void *)user_msg->data + user_msg->len;

	len = le32_to_cpu(in_trans->hdr.len);
	if (user_msg->len + len > QAIC_MANAGE_MAX_MSG_LENGTH) {
		trace_decode_error(qdev, "status trans exceeds msg len");
		return -ENOSPC;
	}

	out_trans->hdr.type = le32_to_cpu(TRANS_STATUS_FROM_DEV);
	out_trans->hdr.len = len;
	out_trans->major = le32_to_cpu(in_trans->major);
	out_trans->minor = le32_to_cpu(in_trans->minor);
	*user_len += in_trans->hdr.len;
	user_msg->len += len;

	return 0;
}

static int decode_message(struct qaic_device *qdev,
			  struct qaic_manage_msg *user_msg, struct _msg *msg,
			  struct ioctl_resources *resources,
			  struct qaic_user *usr)
{
	struct _trans_hdr *trans_hdr;
	u32 msg_len = 0;
	int ret;
	int i;

	if (msg->hdr.len > sizeof(*msg)) {
		trace_decode_error(qdev, "msg to decode len greater than size");
		return -EINVAL;
	}

	user_msg->len = 0;
	user_msg->count = le32_to_cpu(msg->hdr.count);

	for (i = 0; i < user_msg->count; ++i) {
		trans_hdr = (struct _trans_hdr *)(msg->data + msg_len);
		if (msg_len + trans_hdr->len > msg->hdr.len) {
			trace_decode_error(qdev, "trans len exceeds msg len");
			return -EINVAL;
		}

		switch (trans_hdr->type) {
		case TRANS_PASSTHROUGH_FROM_DEV:
			ret = decode_passthrough(qdev, trans_hdr, user_msg,
						 &msg_len);
			break;
		case TRANS_ACTIVATE_FROM_DEV:
			ret = decode_activate(qdev, trans_hdr, user_msg,
					      &msg_len, resources, usr);
			break;
		case TRANS_DEACTIVATE_FROM_DEV:
			ret = decode_deactivate(qdev, trans_hdr, &msg_len);
			break;
		case TRANS_STATUS_FROM_DEV:
			ret = decode_status(qdev, trans_hdr, user_msg,
					    &msg_len);
			break;
		default:
			trace_decode_error(qdev, "unknown trans type");
			return -EINVAL;
		}

		if (ret)
			return ret;
	}

	if (msg_len != (msg->hdr.len - sizeof(msg->hdr))) {
		trace_decode_error(qdev, "decoded msg ended up longer than final trans");
		return -EINVAL;
	}

	return 0;
}

static void *msg_xfer(struct qaic_device *qdev, struct wrapper_msg *wrapper,
		      u32 seq_num, bool ignore_signal)
{
	struct xfer_queue_elem elem;
	struct _msg *out_buf;
	size_t in_len;
	long ret;

	if (qdev->in_reset) {
		mutex_unlock(&qdev->cntl_mutex);
		return ERR_PTR(-ENODEV);
	}

	in_len = sizeof(wrapper->msg);

	elem.seq_num = seq_num;
	elem.buf = NULL;
	init_completion(&elem.xfer_done);
	if (likely(!qdev->cntl_lost_buf)) {
		out_buf = kmalloc(sizeof(*out_buf), GFP_KERNEL);
		if (!out_buf) {
			mutex_unlock(&qdev->cntl_mutex);
			return ERR_PTR(-ENOMEM);
		}

		ret = mhi_queue_transfer(qdev->cntl_ch, DMA_FROM_DEVICE,
					 out_buf, sizeof(*out_buf), MHI_EOT);
		if (ret) {
			mutex_unlock(&qdev->cntl_mutex);
			return ERR_PTR(ret);
		}
	} else {
		/*
		 * we lost a buffer because we queued a recv buf, but then
		 * queuing the corresponding tx buf failed.  To try to avoid
		 * a memory leak, lets reclaim it and use it for this
		 * transaction.
		 */
		qdev->cntl_lost_buf = false;
	}

	kref_get(&wrapper->ref_count);
	ret = mhi_queue_transfer(qdev->cntl_ch, DMA_TO_DEVICE, &wrapper->msg,
				 in_len, MHI_EOT);
	if (ret) {
		qdev->cntl_lost_buf = true;
		kref_put(&wrapper->ref_count, free_wrapper);
		mutex_unlock(&qdev->cntl_mutex);
		return ERR_PTR(ret);
	}

	list_add_tail(&elem.list, &qdev->cntl_xfer_list);
	mutex_unlock(&qdev->cntl_mutex);

	if (ignore_signal)
		ret = wait_for_completion_timeout(&elem.xfer_done,
						  RESP_TIMEOUT);
	else
		ret = wait_for_completion_interruptible_timeout(&elem.xfer_done,
								RESP_TIMEOUT);
	/*
	 * not using _interruptable because we have to cleanup or we'll
	 * likely cause memory corruption
	 */
	mutex_lock(&qdev->cntl_mutex);
	if (!list_empty(&elem.list))
		list_del(&elem.list);
	if (!ret && !elem.buf)
		ret = -ETIMEDOUT;
	else if (ret > 0 && !elem.buf)
		ret = -EIO;
	mutex_unlock(&qdev->cntl_mutex);

	if (ret < 0) {
		kfree(elem.buf);
		return ERR_PTR(ret);
	}

	return elem.buf;
}

static int qaic_manage(struct qaic_device *qdev, struct qaic_user *usr,
		       struct qaic_manage_msg *user_msg)
{
	struct ioctl_resources resources;
	struct wrapper_msg *wrapper;
	struct _msg *msg;
	struct _msg *rsp;
	int ret;

	INIT_LIST_HEAD(&resources.dma_xfers);
	resources.buf = NULL;

	if (user_msg->len > QAIC_MANAGE_MAX_MSG_LENGTH ||
	    user_msg->count >
	    QAIC_MANAGE_MAX_MSG_LENGTH / sizeof(struct qaic_manage_trans_hdr)) {
		trace_manage_error(qdev, usr, "msg from userspace too long or too many transactions");
		ret = -EINVAL;
		goto out;
	}

	wrapper = kzalloc(sizeof(*wrapper), GFP_KERNEL);
	if (!wrapper) {
		trace_manage_error(qdev, usr, "unable to alloc for encode");
		ret = -ENOMEM;
		goto out;
	}

	kref_init(&wrapper->ref_count);
	msg = &wrapper->msg;

	ret = encode_message(qdev, user_msg, msg, &resources, usr);
	if (ret)
		goto encode_failed;

	ret = mutex_lock_interruptible(&qdev->cntl_mutex);
	if (ret)
		goto lock_failed;
	msg->hdr.magic_number = MANAGE_MAGIC_NUMBER;
	msg->hdr.sequence_number = cpu_to_le32(qdev->next_seq_num++);
	msg->hdr.len = cpu_to_le32(msg->hdr.len);
	msg->hdr.count = cpu_to_le32(msg->hdr.count);
	if (usr)
		msg->hdr.handle = cpu_to_le32(usr->handle);
	else
		msg->hdr.handle = 0;

	/* msg_xfer releases the mutex */
	rsp = msg_xfer(qdev, wrapper, qdev->next_seq_num - 1, false);
	if (IS_ERR(rsp)) {
		trace_manage_error(qdev, usr, "failed to xmit to device");
		ret = PTR_ERR(rsp);
		goto lock_failed;
	}

	ret = decode_message(qdev, user_msg, rsp, &resources, usr);

	kfree(rsp);
lock_failed:
	free_dma_xfers(qdev, &resources);
	free_dbc_buf(qdev, &resources);
encode_failed:
	kref_put(&wrapper->ref_count, free_wrapper);
out:
	return ret;
}

int qaic_manage_ioctl(struct qaic_device *qdev, struct qaic_user *usr,
		      unsigned long arg)
{
	struct qaic_manage_msg *user_msg;
	int ret;

	user_msg = kmalloc(sizeof(*user_msg), GFP_KERNEL);
	if (!user_msg) {
		trace_manage_error(qdev, usr, "no mem for userspace message");
		ret = -ENOMEM;
		goto out;
	}

	if (copy_from_user(user_msg, (void __user *)arg, sizeof(*user_msg))) {
		trace_manage_error(qdev, usr, "failed to copy from userspace");
		ret = -EFAULT;
		goto copy_from_user_failed;
	}

	ret = qaic_manage(qdev, usr, user_msg);
	if (ret)
		goto copy_from_user_failed;

	if (copy_to_user((void __user *)arg, user_msg, sizeof(*user_msg))) {
		trace_manage_error(qdev, usr, "failed to copy to userspace");
		ret = -EFAULT;
	}

copy_from_user_failed:
	kfree(user_msg);
out:
	return ret;
}

int get_cntl_version(struct qaic_device *qdev, struct qaic_user *usr,
		     u16 *major, u16 *minor)
{
	int ret;
	struct qaic_manage_msg *user_msg;
	struct qaic_manage_trans_status_to_dev *status_query;
	struct qaic_manage_trans_status_from_dev *status_result;

	user_msg = kmalloc(sizeof(*user_msg), GFP_KERNEL);
	if (!user_msg) {
		ret = -ENOMEM;
		goto out;
	}
	user_msg->len = sizeof(*status_query);
	user_msg->count = 1;

	status_query = (struct qaic_manage_trans_status_to_dev *)user_msg->data;
	status_query->hdr.type = TRANS_STATUS_FROM_USR;
	status_query->hdr.len = sizeof(status_query->hdr);

	ret = qaic_manage(qdev, usr, user_msg);
	if (ret)
		goto kfree_user_msg;
	status_result =
		(struct qaic_manage_trans_status_from_dev *)user_msg->data;
	*major = status_result->major;
	*minor = status_result->minor;

kfree_user_msg:
	kfree(user_msg);
out:
	return ret;
}

static void resp_worker(struct work_struct *work)
{
	struct resp_work *resp = container_of(work, struct resp_work, work);
	struct qaic_device *qdev = resp->qdev;
	struct _msg *msg = resp->buf;
	struct xfer_queue_elem *elem;
	struct xfer_queue_elem *i;
	bool found = false;

	if (msg->hdr.magic_number != MANAGE_MAGIC_NUMBER) {
		kfree(msg);
		kfree(resp);
		return;
	}

	mutex_lock(&qdev->cntl_mutex);
	list_for_each_entry_safe(elem, i, &qdev->cntl_xfer_list, list) {
		if (elem->seq_num == le32_to_cpu(msg->hdr.sequence_number)) {
			found = true;
			list_del_init(&elem->list);
			elem->buf = msg;
			complete_all(&elem->xfer_done);
			break;
		}
	}
	mutex_unlock(&qdev->cntl_mutex);

	if (!found)
		/* request must have timed out, drop packet */
		kfree(msg);

	kfree(resp);
}

void qaic_mhi_ul_xfer_cb(struct mhi_device *mhi_dev,
			 struct mhi_result *mhi_result)
{
	struct _msg *msg = mhi_result->buf_addr;
	struct wrapper_msg *wrapper = container_of(msg, struct wrapper_msg,
						   msg);

	kref_put(&wrapper->ref_count, free_wrapper);
}

void qaic_mhi_dl_xfer_cb(struct mhi_device *mhi_dev,
			 struct mhi_result *mhi_result)
{
	struct qaic_device *qdev = mhi_device_get_devdata(mhi_dev);
	struct _msg *msg = mhi_result->buf_addr;
	struct resp_work *resp;

	if (mhi_result->transaction_status) {
		kfree(msg);
		return;
	}

	resp = kmalloc(sizeof(*resp), GFP_ATOMIC);
	if (!resp) {
		pci_err(qdev->pdev, "dl_xfer_cb alloc fail, dropping message\n");
		kfree(msg);
		return;
	}

	INIT_WORK(&resp->work, resp_worker);
	resp->qdev = qdev;
	resp->buf = msg;
	queue_work(qdev->cntl_wq, &resp->work);
}

int qaic_control_open(struct qaic_device *qdev)
{
	if (!qdev->cntl_ch)
		return -ENODEV;

	return mhi_prepare_for_transfer(qdev->cntl_ch);
}

void qaic_control_close(struct qaic_device *qdev)
{
	mhi_unprepare_from_transfer(qdev->cntl_ch);
}

void qaic_release_usr(struct qaic_device *qdev, struct qaic_user *usr)
{
	struct _trans_terminate_to_dev *trans;
	struct wrapper_msg *wrapper;
	struct _msg *msg;
	struct _msg *rsp;

	wrapper = kzalloc(sizeof(*wrapper), GFP_KERNEL);
	if (!wrapper)
		return;

	kref_init(&wrapper->ref_count);
	msg = &wrapper->msg;

	trans = (struct _trans_terminate_to_dev *)msg->data;

	trans->hdr.type = cpu_to_le32(TRANS_TERMINATE_TO_DEV);
	trans->hdr.len = cpu_to_le32(sizeof(*trans));
	trans->handle = cpu_to_le32(usr->handle);

	mutex_lock(&qdev->cntl_mutex);
	msg->hdr.magic_number = MANAGE_MAGIC_NUMBER;
	msg->hdr.sequence_number = cpu_to_le32(qdev->next_seq_num++);
	msg->hdr.len = cpu_to_le32(sizeof(msg->hdr) + sizeof(*trans));
	msg->hdr.count = cpu_to_le32(1);
	msg->hdr.handle = cpu_to_le32(usr->handle);

	/*
	 * msg_xfer releases the mutex
	 * We don't care about the return of msg_xfer since we will not do
	 * anything different based on what happens.
	 * We ignore pending signals since one will be set if the user is
	 * killed, and we need give the device a chance to cleanup, otherwise
	 * DMA may still be in progress when we return.
	 */
	rsp = msg_xfer(qdev, wrapper, qdev->next_seq_num - 1, true);
	if (!IS_ERR(rsp))
		kfree(rsp);
	kref_put(&wrapper->ref_count, free_wrapper);
}

void wake_all_cntl(struct qaic_device *qdev)
{
	struct xfer_queue_elem *elem;
	struct xfer_queue_elem *i;

	mutex_lock(&qdev->cntl_mutex);
	list_for_each_entry_safe(elem, i, &qdev->cntl_xfer_list, list) {
		list_del_init(&elem->list);
		complete_all(&elem->xfer_done);
	}
	mutex_unlock(&qdev->cntl_mutex);
}
