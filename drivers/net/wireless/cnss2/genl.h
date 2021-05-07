/* SPDX-License-Identifier: GPL-2.0-only */
/* Copyright (c) 2019-2021, The Linux Foundation. All rights reserved. */

#ifndef __CNSS_GENL_H__
#define __CNSS_GENL_H__

#include <net/netlink.h>
#include <net/genetlink.h>

#define CNSS_GENL_STR_LEN_MAX 32
enum cnss_genl_msg_type {
	CNSS_GENL_MSG_TYPE_UNSPEC,
	CNSS_GENL_MSG_TYPE_QDSS,
	CNSS_GENL_MSG_TYPE_DAEMON_SUPPORT,
	CNSS_GENL_MSG_TYPE_COLD_BOOT_SUPPORT,
	CNSS_GENL_MSG_TYPE_CALDATA_SUPPORT
};

int cnss_genl_init(void);
void cnss_genl_exit(void);
int cnss_genl_send_msg(void *buff, u8 type,
		       char *file_name, u32 total_size);
int cnss_genl_process_msg(struct sk_buff *skb, struct genl_info *info);

#endif
