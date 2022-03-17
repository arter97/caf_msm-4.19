// SPDX-License-Identifier: GPL-2.0-only

/**
 * Driver for control fan on QRB5165.
 *
 * Copyright (c) 2020, The Linux Foundation. All rights reserved.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/of_gpio.h>
#include <linux/gpio.h>
#include <linux/kernel.h>

#define DEV_NAME "rb5_fan"
#define DEV_SIZE 10
#define HIGH 1
#define HIGH_SPEED '1'
#define LOW_SPEED '0'
#define LOW 0
#define ZERO 0
#define FAN_HIGH_SPEED "1(high)\n"
#define FAN_LOW_SPEED "0(low)\n"

static int major;
static struct class *fan_class;

static u32 pwr_enable_gpio;
static char fan_speed_char[DEV_SIZE] = "NULL\n";
#define DEV_SIZE 10

static int fan_speed_set(int fan_speed)
{
	int ret;
	int fan_speed_var = fan_speed;
	if(fan_speed_var != HIGH && fan_speed_var != LOW)
		return -1;
	else if(fan_speed_var == HIGH)
		gpio_set_value(pwr_enable_gpio, LOW);
	else
		gpio_set_value(pwr_enable_gpio, HIGH);
	if(gpio_get_value(pwr_enable_gpio) == fan_speed_var)
		ret = -1;
	else{
		memset(fan_speed_char,0,strlen(fan_speed_char));
		if(fan_speed == HIGH)
			strncpy(fan_speed_char, FAN_HIGH_SPEED ,strlen(FAN_HIGH_SPEED));
		else
			strncpy(fan_speed_char, FAN_LOW_SPEED ,strlen(FAN_HIGH_SPEED));
		ret = 0;
	}
	return ret;
}

static ssize_t fan_status_get(struct file *filep, char *buf, size_t count, loff_t * f_pos)
{
	int fan_speed_var = -1;
	int ret = 0;
	if(!f_pos){
		return 0;
	}
	unsigned long offset = *f_pos;
	unsigned int count_var = count;
	unsigned int dev_size = strlen(fan_speed_char)+1;
	if(offset > dev_size){
		pr_debug("offset > dev_size ");
		return count_var ? - ENXIO: 0;
	}
	else if(offset == dev_size){
		pr_debug("offset = dev_size");
		return 0;
	}
	if(count_var  > dev_size - offset){
		pr_debug("count > DEV_SIZE - offset");
		count_var = dev_size - offset;
	}
	if(copy_to_user(buf,&fan_speed_char,strlen(fan_speed_char)+1)){
		return -EFAULT;
	}
	else{
		*f_pos += count_var;
		pr_debug("read %d bytes from %ld offset \n",count_var,offset);
		ret = count_var;
	}
	return ret;
}

static  ssize_t fan_status_set(struct file *filep, const char *buf, size_t count, loff_t * f_pos)
{
	unsigned long offset = *f_pos;
	int ret = -1;
	if(count > DEV_SIZE){
		return -1;
	}
	char fan_speed_var[DEV_SIZE] = "NULL\n";
	if(copy_from_user(&fan_speed_var,buf,count)){
		pr_err("copy_from_user failed");
		return -EFAULT;
	}
	if(fan_speed_var[ZERO] == LOW_SPEED){
		ret = fan_speed_set(LOW);
	}
	else if(fan_speed_var[ZERO] == HIGH_SPEED){
		ret = fan_speed_set(HIGH);
	}
	else{
		pr_err("rb5_fan : invailid input %s",fan_speed_char);
		return -1;
	}
	if(!ret){
		pr_debug("*******************set speed %s ************************ end : len=%d\n",fan_speed_char,count);
	}
	else
		pr_debug("*******************set speed %s failed************************\n",fan_speed_char);
	return count;
}

static const struct file_operations fan_fops = {
	.owner		= THIS_MODULE,
	.read 		= fan_status_get,
	.write 		= fan_status_set,
};
static int fan_probe(struct platform_device *pdev)
{
	struct device *dev = NULL;
	struct device_node *np = pdev->dev.of_node;

	pr_debug(DEV_NAME ": probe\n");

	major = register_chrdev(0, DEV_NAME, &fan_fops);
	if (major < 0) {
		pr_warn(DEV_NAME ": unable to get major %d\n", major);
		return major;
	}
	fan_class = class_create(THIS_MODULE, DEV_NAME);
	if (IS_ERR(fan_class))
		return PTR_ERR(fan_class);

	dev = device_create(fan_class, NULL, MKDEV(major, 0), NULL, DEV_NAME);
	if (IS_ERR(dev)) {
		pr_err(DEV_NAME ": failed to create device %d\n", dev);
		return PTR_ERR(dev);
	}
	pwr_enable_gpio = of_get_named_gpio(np, "qcom,pwr-enable-gpio", 0);
	if (!gpio_is_valid(pwr_enable_gpio)) {
		pr_err("%s qcom,pwr-enable-gpio not specified\n", __func__);
		goto error;
	}
	if (gpio_request(pwr_enable_gpio, "qcom,pwr-enable-gpio")) {
		pr_err("qcom,pwr-enable-gpio request failed\n");
		goto error;
	}
	gpio_direction_output(pwr_enable_gpio, 0);
	fan_speed_set(LOW);
	pr_debug("%s gpio:%d set to high default\n", __func__, pwr_enable_gpio);
	return 0;

error:
	gpio_free(pwr_enable_gpio);
	return -EINVAL;
}

static int fan_remove(struct platform_device *pdev)
{
	pr_debug(DEV_NAME ": remove\n");
	gpio_free(pwr_enable_gpio);
	device_destroy(fan_class, MKDEV(major, 0));
	class_destroy(fan_class);
	unregister_chrdev(major, DEV_NAME);
	return 0;
}

static const struct of_device_id of_fan_dt_match[] = {
	{.compatible	= "qcom,rb5_fan_controller"},
	{},
};

MODULE_DEVICE_TABLE(of, of_fan_dt_match);

static struct platform_driver fan_driver = {
	.probe	= fan_probe,
	.remove	= fan_remove,
	.driver	= {
		.name	= DEV_NAME,
		.of_match_table	= of_fan_dt_match,
	},
};

static int __init fan_init(void)
{
	pr_debug(DEV_NAME ": init\n");
	return platform_driver_register(&fan_driver);
}

static void __exit fan_exit(void)
{
	pr_debug(DEV_NAME ": exit\n");
	platform_driver_unregister(&fan_driver);
}

module_init(fan_init);
module_exit(fan_exit);

MODULE_DESCRIPTION("Driver to control fan");
MODULE_LICENSE("GPL v2");
