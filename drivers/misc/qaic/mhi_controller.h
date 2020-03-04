/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Copyright (c) 2019-2020, The Linux Foundation. All rights reserved.
 */

#ifndef MHICONTROLLERQAIC_H_
#define MHICONTROLLERQAIC_H_

struct mhi_controller *qaic_mhi_register_controller(struct pci_dev *pci_dev,
						    void *mhi_bar,
						    int mhi_irq);

void qaic_mhi_free_controller(struct mhi_controller *mhi_cntl, bool link_up);

void qaic_mhi_link_down(struct mhi_controller *mhi_cntl);
void qaic_mhi_link_up(struct mhi_controller *mhi_cntl);
void qaic_mhi_start_reset(struct mhi_controller *mhi_cntl);
void qaic_mhi_reset_done(struct mhi_controller *mhi_cntl);

#endif /* MHICONTROLLERQAIC_H_ */
