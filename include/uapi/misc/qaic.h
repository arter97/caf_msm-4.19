/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 *
 * Copyright (c) 2019-2020, The Linux Foundation. All rights reserved.
 */

#ifndef QAIC_H_
#define QAIC_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define QAIC_MANAGE_MAX_MSG_LENGTH 16364

enum qaic_sem_flags {
	SEM_INSYNCFENCE =	0x1,
	SEM_OUTSYNCFENCE =	0x2,
};

enum qaic_sem_cmd {
	SEM_NOP =		0,
	SEM_INIT =		1,
	SEM_INC =		2,
	SEM_DEC =		3,
	SEM_WAIT_EQUAL =	4,
	SEM_WAIT_GT_EQ =	5, /* Greater than or equal */
	SEM_WAIT_GT_0 =		6, /* Greater than 0 */
};

enum qaic_manage_transaction_type {
	TRANS_UNDEFINED =		0,
	TRANS_PASSTHROUGH_FROM_USR =	1,
	TRANS_PASSTHROUGH_TO_USR =	2,
	TRANS_PASSTHROUGH_FROM_DEV =	3,
	TRANS_PASSTHROUGH_TO_DEV =	4,
	TRANS_DMA_XFER_FROM_USR =	5,
	TRANS_DMA_XFER_TO_DEV =		6,
	TRANS_ACTIVATE_FROM_USR =	7,
	TRANS_ACTIVATE_FROM_DEV =	8,
	TRANS_ACTIVATE_TO_DEV =		9,
	TRANS_DEACTIVATE_FROM_USR =	10,
	TRANS_DEACTIVATE_FROM_DEV =	11,
	TRANS_STATUS_FROM_USR =		12,
	TRANS_STATUS_TO_USR =		13,
	TRANS_STATUS_FROM_DEV =		14,
	TRANS_STATUS_TO_DEV =		15,
	TRANS_TERMINATE_FROM_DEV =	16,
	TRANS_TERMINATE_TO_DEV =	17,
	TRANS_MAX =			18
};

struct qaic_manage_trans_hdr {
	__u32 type; /* value from enum manage_transaction_type */
	__u32 len;  /* length of this transaction, including the header */
};

struct qaic_manage_trans_passthrough {
	struct qaic_manage_trans_hdr hdr;
	u8 data[0]; /* userspace must encode in little endian */
};

struct qaic_manage_trans_dma_xfer {
	struct qaic_manage_trans_hdr hdr;
	__u32 tag;
	__u32 count;
	__u64 addr;
	__u64 size;
};

struct qaic_manage_trans_activate_to_dev {
	struct qaic_manage_trans_hdr hdr;
	__u32 queue_size; /* in number of elements */
	__u32 eventfd;
	__u64 resv; /* reserved for future use, must be 0 */
};

struct qaic_manage_trans_activate_from_dev {
	struct qaic_manage_trans_hdr hdr;
	__u32 status;
	__u32 dbc_id; /* Identifier of assigned DMA Bridge channel */
};

struct qaic_manage_trans_deactivate {
	struct qaic_manage_trans_hdr hdr;
	__u32 dbc_id; /* Identifier of assigned DMA Bridge channel */
	__u32 resv;   /* reserved for future use, must be 0 */
};

struct qaic_manage_trans_status_to_dev {
	struct qaic_manage_trans_hdr hdr;
};

struct qaic_manage_trans_status_from_dev {
	struct qaic_manage_trans_hdr hdr;
	__u16 major;
	__u16 minor;
	__u32 status;
};

struct qaic_manage_msg {
	__u32 len;   /* Length of valid data - ie sum of all transactions */
	__u32 count; /* Number of transactions in message */
	__u8 data[QAIC_MANAGE_MAX_MSG_LENGTH];
};

struct qaic_mem_req {
	__u64 handle; /* 0 to alloc, or a valid handle to free */
	__u64 size;   /* size to alloc, will be rounded to PAGE_SIZE */
	__u32 dir;    /* direction of data: 0 = bidirectional data,
			 1 = to device, 2 = from device */
	__u32 dbc_id; /* Identifier of assigned DMA Bridge channel */
	__u64 resv;   /* reserved for future use, must be 0 */
};

struct qaic_sem { /* semaphore command */
	__u16 val;     /* only lower 12 bits are valid */
	__u8  index;   /* only lower 5 bits are valid */
	__u8  presync; /* 1 if presync operation, 0 if postsync */
	__u8  cmd;     /* see enum sem_cmd */
	__u8  flags;   /* see sem_flags for valid bits.  All others must be 0 */
	__u16 resv;    /* reserved for future use, must be 0 */
};

struct qaic_execute {
	__u16		ver;    /* struct version, must be 1 */
	__u8		dir;    /* 1 = to device, 2 = from device */
	__u8		db_len; /* doorbell length - 32, 16, or 8 bits. 0 means
				   doorbell is inactive */
	__u32		db_data;/* data to write to doorbell */
	__u64		db_addr;/* doorbell address */
	__u64		handle; /* mem handle from mem_req */
	__u64		dev_addr;
	__u32		dbc_id; /* Identifier of assigned DMA Bridge channel */
	__u32		resv;   /* reserved for future use, must be 0 */
	struct qaic_sem	sem0;   /* Must be zero if not valid */
	struct qaic_sem	sem1;   /* Must be zero if not valid */
	struct qaic_sem	sem2;   /* Must be zero if not valid */
	struct qaic_sem	sem3;   /* Must be zero if not valid */
};

struct qaic_wait_exec {
	__u64 handle; /* handle to wait on until execute is complete */
	__u32 timeout;/* timeout for wait(in ms) */
	__u32 resv;   /* reserved for future use, must be 0 */
};

#define QAIC_IOCTL_MANAGE_NR	0x01
#define QAIC_IOCTL_MEM_NR	0x02
#define QAIC_IOCTL_EXECUTE_NR	0x03
#define QAIC_IOCTL_WAIT_EXEC_NR	0x04

/*
 * Send Manage command to the device
 *
 * A manage command is a message that consists of N transactions.  The set
 * of transactions consititues a single operation.  In most cases, a manage
 * command is a request for the device to do something.  The entire command
 * must be encoded into a single message.
 *
 * The command will be encoded into the wire format, and sent to the device.
 * the process will then be blocked until the device responds to the message
 * or a timeout is reached.  If a response is successfully received, it will
 * be encoded into the provided message structure.
 *
 * The return value is 0 for success, or a standard error code.  Some of the
 * possible errors:
 *
 * EINTR     - Kernel waiting was interrupted (IE received a signal for user)
 * ETIMEDOUT - Timeout for response from device expired
 * EINVAL    - Invalid message
 * ENOSPC    - Ran out of space to encode the message into the wire protocol
 * ENOMEM    - Unable to obtain memory while processing message
 * EFAULT    - Error in accessing memory from user
 */
#define QAIC_IOCTL_MANAGE _IOWR('Q', QAIC_IOCTL_MANAGE_NR, struct manage_msg)

/*
 * Memory alloc/free
 *
 * Allows user to request buffers to send/receive data to/from the device
 * via a DMA Bridge channel.  An allocated buffer may then be mmap'd to be
 * accessed.  Buffers are tied to a specific dbc.  It is expected that the
 * user will request a pool of buffers, and reuse the buffers as necessary
 * to send/receive multiple sets of data with the device over time.
 *
 * The handle to the allocated buffer will be returned in the struct upon
 * success.  A buffer to be freed cannot be accessed after the ioctl is called.
 *
 * A request for a 0 size buffer is valid.  This signals that the DMA
 * operation to/from the device does not transfer data, but does perform
 * other tasks (ring doorbell, etc).  A handle from a zero size request cannot
 * be mmap()'d.
 *
 * The return value is 0 for success, or a standard error code.  Some of the
 * possible errors:
 *
 * EINTR  - Kernel waiting was interrupted (IE received a signal for user)
 * ENOMEM - Unable to obtain memory while processing request
 * EPERM  - Invalid permissions to access resource
 * EINVAL - Invalid request
 * EFAULT - Error in accessing memory from user
 * ENODEV - Resource does not exist
 */
#define QAIC_IOCTL_MEM _IOWR('Q', QAIC_IOCTL_MEM_NR, struct mem_req)

/*
 * Execute DMA Bridge transaction
 *
 * Allows user to execute a DMA Bridge transaction using a previously allocated
 * memory resource.  This operation is non-blocking - success return only
 * indicates the transaction is queued with the hardware, not that it is
 * complete.  The user must ensure that the transaction is complete before
 * reusing the memory resource.  It is invalid to attempt to execute multiple
 * transactions concurrently which use the same memory resource in the same
 * direction.
 *
 * The return value is 0 for success, or a standard error code.  Some of the
 * possible errors:
 *
 * ENOMEM - Unable to obtain memory while processing request
 * EPERM  - Invalid permissions to access resource
 * EINVAL - Invalid request
 * EFAULT - Error in accessing memory from user
 * ENODEV - Resource does not exist
 */
#define QAIC_IOCTL_EXECUTE _IOW('Q', QAIC_IOCTL_EXECUTE_NR, struct execute)

/*
 * TODO writeup
 */
#define QAIC_IOCTL_WAIT_EXEC _IOW('Q', QAIC_IOCTL_WAIT_EXEC_NR,	\
				  struct wait_exec)

#endif /* QAIC_H_ */
