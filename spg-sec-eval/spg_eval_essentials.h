/*
 * spg_device_essentials.h -- The header file that contains a number of
 * definitions required for the operation of the SpecProbeGuard security
 * evaluation kernel module.
 */

#ifndef SPG_DEVICE_ESSENTIALS_H
#define SPG_DEVICE_ESSENTIALS_H

#include <linux/ioctl.h>

// -- IOCTL REGISTRATION --

/*
 * Major device number for ioctl registration. Should be free in:
 * $ cat /proc/devices.
 */
#define MAJOR_NUM 169

// -- AVAILABLE DEVICE COMMANDS --

/*
 * List of currently defined commands for the defence manager device.
 */
#define IOCTL_SPG_EVAL_KM_NOP                       _IO(MAJOR_NUM,  0)
#define IOCTL_SPG_EVAL_KM_KERNEL_BASE_ATT           _IO(MAJOR_NUM,  1)
#define IOCTL_SPG_EVAL_KM_GADGET_ATT                _IO(MAJOR_NUM,  2)
#define IOCTL_SPG_EVAL_KM_ADV_GADGET_ATT            _IO(MAJOR_NUM,  3)
#define IOCTL_SPG_EVAL_KM_ADV_GADGET_ATT_RAND       _IO(MAJOR_NUM,  4)
#define IOCTL_SPG_EVAL_KM_TRAP_SENS_SIM             _IO(MAJOR_NUM,  5)

// -- DEVICE FILE INFORMATION --

/*
 * Name of the device file. When finished (i.e., not sample), this should be
 * changed to a filepath in the /dev/ directory, e.g.:
 * 
 * /dev/spg_defence_device (or something like this).
 */
#define DEVICE_FILE_NAME "spg_eval"
#define DEVICE_FILE_PATH "/path/to/spg_eval"

#endif