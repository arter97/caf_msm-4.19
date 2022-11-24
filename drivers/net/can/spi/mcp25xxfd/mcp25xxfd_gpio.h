/* SPDX-License-Identifier: GPL-2.0 */

/* CAN bus driver for Microchip 25XXFD CAN Controller with SPI Interface
 *
 * Copyright 2019 Martin Sperl <kernel@martin.sperl.org>
 */
#ifndef __MCP25XXFD_GPIO_H
#define __MCP25XXFD_GPIO_H

#include "mcp25xxfd_priv.h"

/* gpiolib support */
int mcp25xxfd_gpio_setup(struct mcp25xxfd_priv *priv);
void mcp25xxfd_gpio_remove(struct mcp25xxfd_priv *priv);
int g_mcp25xxfd_gpio_direction_output(struct gpio_chip *chip,
				      unsigned int offset, int value);


#endif /* __MCP25XXFD_GPIO_H */
