/*
 * kmod_spg_eval_user.c -- The user space program that goes with the
 * SpecProbeGuard Evaluation kernel mod device. Enables a user to insert debug
 * commands and such to allow for debugging, testing, and evaluation.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <string.h>
#include <errno.h>

#include <sys/ioctl.h>

#include "spg_eval_essentials.h"

// -- GLOBALS --

int file_desc;

// -- DEVICE --

int kmod_tryout_dev_close(){
	return close(file_desc);
}

int kmod_tryout_dev_open(){
	int ret_val;
	ret_val = 0;

	file_desc = open(DEVICE_FILE_PATH, 0);
	if(file_desc < 0){
		ret_val = -1;
	}
	
	return ret_val;
}

// -- ATTACK REQUEST AND RESULT RETRIEVAL --

int main(int argc, char *argv[]){
	int ret_val;
	ret_val = 0;

	int spec_accesses;
	spec_accesses = 0;

	file_desc = 0;

	printf("INFO: Attempting to access the SpecProbeGuard Evaluation kernel module...\n");

	if(kmod_tryout_dev_open() < 0){
		printf("ERROR: Failed to open device file: %s (%s). Exiting.\n", DEVICE_FILE_PATH, strerror(errno));
	
		ret_val = -1;
		goto out;
	}

	printf("SUCCESS: Opened associated device file.\n");

	printf("INFO: Attempting to execute command...\n");

	if(*argv[1] == '1'){
		ret_val = ioctl(file_desc, IOCTL_SPG_EVAL_KM_KERNEL_BASE_ATT);
	}else if(*argv[1] == '2'){
		ret_val = ioctl(file_desc, IOCTL_SPG_EVAL_KM_GADGET_ATT);
	}else if(*argv[1] == '3'){
		if(argc < 3){
			printf("ERROR: Command (%u) requires two arguments. Exiting.\n", IOCTL_SPG_EVAL_KM_ADV_GADGET_ATT);

			ret_val = -1;
			goto out;
		}
		
		ret_val = ioctl(file_desc, IOCTL_SPG_EVAL_KM_ADV_GADGET_ATT, atoi(argv[2]));
	}else if(*argv[1] == '4'){
		ret_val = ioctl(file_desc, IOCTL_SPG_EVAL_KM_ADV_GADGET_ATT_RAND);
	}else if(*argv[1] == '5'){
		ret_val = ioctl(file_desc, IOCTL_SPG_EVAL_KM_TRAP_SENS_SIM);
	}

	printf("INFO: Attempting to close associated device file...\n");

	if(kmod_tryout_dev_close() < 0){
		printf("ERROR: Failed to close device file: %s. Exiting.\n", DEVICE_FILE_PATH);
		
		ret_val = -1;
		goto out;
	}

	printf("SUCCESS: Closed associated device file. Exiting.\n");

out:
	return ret_val;
}