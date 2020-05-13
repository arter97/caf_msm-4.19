# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for QTI Cloud AI accelerators driver
#

#setup for TRACE_INCLUDE_PATH for various build environments
subdir-ccflags-y := -I$(src)

obj-$(CONFIG_QAIC)	:= qaic.o

qaic-y := \
	qaic_drv.o \
	mhi_controller.o \
	qaic_control.o \
	qaic_data.o \
	qaic_debugfs.o \
	qaic_telemetry.o \
	qaic_ras.o
