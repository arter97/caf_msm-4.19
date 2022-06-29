/*
 * SPDX-License-Identifier: GPL-2.0-only
 * Copyright (c) 2022 Qualcomm Innovation Center, Inc. All rights reserved.
 */
#define ICE_IOC_MAGIC        0X17

struct partition_info {
    unsigned char* partition_name;
    unsigned int len;
};

#define ICE_IOCTL_GET_PARTITION_NAME _IOWR(ICE_IOC_MAGIC, 5, struct partition_info)