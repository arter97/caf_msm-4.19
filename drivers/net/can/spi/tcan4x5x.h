// SPDX-License-Identifier: GPL-2.0
// SPI to CAN driver for the Texas Instruments TCA4x5x
// Flash driver chip family
// Copyright (C) 2018 Texas Instruments Incorporated - http://www.ti.com/

#define TCAN4X5X_DEV_ID0	0x00
#define TCAN4X5X_DEV_ID1	0x04
#define TCAN4X5X_REV		0x08
#define TCAN4X5X_STATUS		0x0C
#define TCAN4X5X_ERROR_STATUS	0x10
#define TCAN4X5X_CONTROL	0x14

#define TCAN4X5X_CONFIG		0x800
#define TCAN4X5X_TS_PRESCALE	0x804
#define TCAN4X5X_TEST_REG	0x808
#define TCAN4X5X_INT_FLAGS	0x820
#define TCAN4X5X_MCAN_INT_REG	0x824
#define TCAN4X5X_INT_EN		0x830

#define TCAN4X5X_MCAN_CREL	0x1000
#define TCAN4X5X_MCAN_ENDN	0x1004
#define TCAN4X5X_MCAN_CUST	0x1008
#define TCAN4X5X_MCAN_DBTP	0x100C
#define TCAN4X5X_MCAN_TEST	0x1010
#define TCAN4X5X_MCAN_RWD	0x1014
#define TCAN4X5X_MCAN_CCCR	0x1018
#define TCAN4X5X_MCAN_NBTP	0x101C
#define TCAN4X5X_MCAN_TSCC	0x1020
#define TCAN4X5X_MCAN_TSCV	0x1024
#define TCAN4X5X_MCAN_TOCC	0x1028
#define TCAN4X5X_MCAN_TOCV	0x102C
#define TCAN4X5X_MCAN_ECR	0x1040
#define TCAN4X5X_MCAN_PSR	0x1044
#define TCAN4X5X_MCAN_TDCR	0x1048
#define TCAN4X5X_MCAN_INT_FLAG	0x1050
#define TCAN4X5X_MCAN_INT_EN	0x1054
#define TCAN4X5X_MCAN_ILS	0x1058
#define TCAN4X5X_MCAN_ILE	0x105C
#define TCAN4X5X_MCAN_GFC	0x1080
#define TCAN4X5X_MCAN_SIDFC	0x1084
#define TCAN4X5X_MCAN_XIDFC	0x1088
#define TCAN4X5X_MCAN_XIDAM	0x1090
#define TCAN4X5X_MCAN_HPMS	0x1094
#define TCAN4X5X_MCAN_NDAT1	0x1098
#define TCAN4X5X_MCAN_NDAT2	0x109C
#define TCAN4X5X_MCAN_RXF0C	0x10A0
#define TCAN4X5X_MCAN_RXF0S	0x10A4
#define TCAN4X5X_MCAN_RXF0A	0x10A8
#define TCAN4X5X_MCAN_RXBC	0x10AC
#define TCAN4X5X_MCAN_RXF1C	0x10B0
#define TCAN4X5X_MCAN_RXF1S	0x10B4
#define TCAN4X5X_MCAN_RXF1A	0x10B8
#define TCAN4X5X_MCAN_RXESC	0x10BC
#define TCAN4X5X_MCAN_TXBC	0x10C0
#define TCAN4X5X_MCAN_TXFQS	0x10C4
#define TCAN4X5X_MCAN_TXESC	0x10C8
#define TCAN4X5X_MCAN_TXBRP	0x10CC
#define TCAN4X5X_MCAN_TXBAR	0x10D0
#define TCAN4X5X_MCAN_TXBCR	0x10D4
#define TCAN4X5X_MCAN_TXBTO	0x10D8
#define TCAN4X5X_MCAN_TXBCF	0x10DC
#define TCAN4X5X_MCAN_TXBTIE	0x10E0
#define TCAN4X5X_MCAN_TXBCIE	0x10E4
#define TCAN4X5X_MCAN_TXEFC	0x10F0
#define TCAN4X5X_MCAN_TXEFS	0x10F4
#define TCAN4X5X_MCAN_TXEFA	0x10F8

#define TCAN4X5X_MRAM_START	0x8000
#define TCAN4X5X_MRAM_SIZE	2048

#define TCAN4X5X_MAX_REGISTER	0x8fff

#define TCAN4X5X_BUF_LEN 72

struct tcan4x5x_priv {
	struct can_priv can;
	struct net_device *net;
	struct regmap *regmap;
	struct spi_device *spi;

	struct mutex tcan4x5x_lock; /* SPI device lock */

	struct gpio_desc *reset_gpio;
	struct gpio_desc *interrupt_gpio;
	struct gpio_desc *wake_gpio;
	struct regulator *power;
	struct clk *clk;

	struct sk_buff *tx_skb;
	int tx_len;

	struct workqueue_struct *wq;
	struct work_struct tx_work;
	struct work_struct restart_work;

	u32 *spi_tx_buf;
	u32 *spi_rx_buf;

	int force_quit;
	int after_suspend;
#define AFTER_SUSPEND_UP 1
#define AFTER_SUSPEND_DOWN 2
#define AFTER_SUSPEND_POWER 4
#define AFTER_SUSPEND_RESTART 8
	int restart_tx;

	int irq;
};

int tcan4x5x_init_debug(struct tcan4x5x_priv *tcan4x5x);
int tcan4x5x_hw_rx(struct tcan4x5x_priv *tcan4x5x);
