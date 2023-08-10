/*
 * spg_device_essentials.h -- The header file that contains a number of definitions
 * required for the operation of the SpecProbeGuard defence manager kernel module.
 */

#ifndef SPG_DEVICE_ESSENTIALS_H
#define SPG_DEVICE_ESSENTIALS_H

#include <linux/ioctl.h>

// -- IOCTL REGISTRATION --

/*
 * Major device number for the purpose of ioctl registration. Should be free in:
 * $ cat /proc/devices.
 */
#define MAJOR_NUM 168

// -- AVAILABLE DEVICE COMMANDS --

/*
 * List of currently defined commands for the defence manager device.
 */
#define IOCTL_SPG_KM_NOP                       _IO(MAJOR_NUM,  0)
#define IOCTL_SPG_KM_GET_COUNTER_STATUS        _IO(MAJOR_NUM,  1)
#define IOCTL_SPG_KM_SWITCH_KEY_ENABLE_PARAM   _IO(MAJOR_NUM,  2)
#define IOCTL_SPG_KM_SWITCH_KEY_DISABLE_PARAM  _IO(MAJOR_NUM,  3)

// -- DEVICE FILE INFORMATION --

/*
 * Name of the device file. When finished (i.e., not sample), this should be changed to a filepath
 * in the /dev/ directory: /dev/spg_defence_device (or something like this).
 */
#define DEVICE_FILE_NAME "spg_manager"
#define DEVICE_FILE_PATH "/home/daveq/Desktop/msc_project/kmods/spg_manager_workqueue/spg_manager"

#endif