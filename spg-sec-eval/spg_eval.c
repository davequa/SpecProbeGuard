/*
 * spg_eval.c -- A kernel module that contains all necessary elements to mimic
 * realistic attack scenarios to evaluate the SpecProbeGuard defence. In short,
 * it launches a sample BlindSide attack (the strongest variant possible, i.e.,
 * using an ideal Spectre gadget, unrealistically accurate probes, etc.) in
 * order to launch speculative probes into the kernel address space, with how
 * it does so (e.g., at which granularity it probes, at which speed, etc.) being
 * configurable for different experiments -- with each experiment simulating one
 * of the various parts of the existing exploits fashioned by Goktas et al. in
 * their 'BlindSide' paper (CCS 2020), or similar and representative.
 *
 * In this simulation, we assume that every probe an attacker launches is
 * successful, meaning that if they hit any memory address that will provide an
 * attacker with feedback through their covert channel, it will. Further, if
 * such a probe hits an address with a targeted code gadget, we will assume the
 * gadget can be used in an attack, and the defence has failed.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cpufeature.h>

#include <linux/fs.h>
#include <linux/time.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/unistd.h>

#include <linux/delay.h>

#include <linux/random.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

#include <asm/cmdline.h>

// -- INCLUDED FILES AND DEVICE DEFINITIONS --

#include "spg_eval_essentials.h"
#include "/path/to/include/spg_header.h"

#define DRIV_NAME "SPG Security Evaluation Kernel Module -- Simulating realistic speculative probing attacks"
#define MOD_AUTHOR "daveq"
#define MOD_DESC "A kernel module evaluating the security guarantees of SpecProbeGuard."
#define MOD_VERSION "0.1"
#define MOD_LICENSE "GPL"

MODULE_LICENSE(MOD_LICENSE);
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_DESCRIPTION(MOD_DESC);
MODULE_VERSION(MOD_VERSION);

#define DEVICE_NAME "spg_eval"

// -- BLINDSIDE ATTACK ESSENTIALS --

/* Forced inlining definition for speeding up functions/code. */
#define FORCE_INLINE __attribute__ ((always_inline)) static inline

FORCE_INLINE void flush(void *p){
	asm volatile("clflush 0(%0)\n" : : "c" (p) : "rax");
}

FORCE_INLINE void mfence(void){
	asm volatile("mfence");
}

FORCE_INLINE void lfence(void){
	asm volatile("lfence");
}

FORCE_INLINE int maccess(void *p){
	asm volatile("movq (%0), %%rax\n" : : "c" (p) : "rax");
}

#define NUM_PROBES 1
#define NUM_OBJS 33 // Slightly above 32, e.g., 33, greatly improves effects.
#define NUM_TOTAL_ITER (NUM_PROBES * NUM_OBJS)

#define TARGET_OBJ (NUM_OBJS - 1)

/*
 * The offset to the fp_enabled pointer inside the blindside_obj_t struct.
 * Adding it to the attack's operation helps improve the odds of successful
 * exploitation by increasing the size of the speculation window.
 */
int fp_enabled_offset;

typedef struct blindside_obj_t{
	int pad[64];
	int fp_enabled;
	char fill[64]; // Adding more padding (64 to 256, 1024) makes no difference.
	void (*fp)();
}blindside_obj_t;

/*
 * Array of probing objects for the BlindSide exploit, stored globally as the
 * local function frame is not sufficiently large for NUM_OBJS > 16. Using a
 * few more objects seems to help the exploit, so keep it like this for now.
 */
blindside_obj_t objs[NUM_OBJS];

FORCE_INLINE void blindside_func(blindside_obj_t* obj){
	int *x;
	x = &fp_enabled_offset;

	flush(&x);
	flush(x);
	flush(&obj->fp_enabled);

	/*
	 * Touch the function pointer of the object already here to shorten the
	 * induced second speculative window, avoiding the situation where this
	 * window extends beyond the first (which we specifically require to be
	 * sufficiently long(er) for the exploit).
	 *
	 * We remove this optimisation from this evaluation, since it means that, if
	 * the target is an unmapped address, an unmapped address may be considered
	 * architecturally. This is detected by the kernel, which will trap.
	 */
	// maccess(obj->fp);

	mfence();

	if(obj->pad[*x]){
		/*
		 * In case the condition was true, this function pointer leads to a
		 * training (benign) function. After training the CPU a number of times,
		 * we switch the condition to false and change the function pointer to
		 * lead to our probing target. Consequently, speculation will be
		 * induced (due to training), and the target address will be executed.
		 */
		obj->fp();
	}
}

// -- BLINDSIDE SIMULATION: ESSENTIALS --

/*
 * Since this is a simulation, we pre-determine the location of the kernel
 * image's base beforehand manually at this time. Since it is an enormous hassle
 * to do this dynamically (during run-time), and we want to save time now, just
 * do it manually before the evaluation each time.
 *
 * If KASLR is disabled, the base address will always be 0xffffffff81000000.
 */
// #define KERNEL_BASE_ADDR 0xffffffff81000000
#define KERNEL_BASE_ADDR 0xffffffff81800000

/*
 * We pre-determine the range of the kernel's image (in bytes) in which the
 * attacker will probe. Namely, not all regions of the kernel contain code
 * that is interesting or realistically probe-able. Hence, we select only the
 * .text region of the kernel to contain our targets at this time.
 *
 * This is assuming coarse-grained KASLR is disabled for easier
 * experimentation. Since it does not matter for the experiments, we just leave
 * KASLR deactivated for the time being.
 */
#define KERNEL_STOCK_TEXT_SECTION_START_ADDR KERNEL_BASE_ADDR
#define KERNEL_STOCK_TEXT_SECTION_END_ADDR 0xffffffff820031fb

#define KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR KERNEL_BASE_ADDR
#define KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR 0xffffffff8240325b

/*
 * The number of probes we assume an attacker launches at a single location
 * before moving on to the next location to probe.
 *
 * The range we test is: 1, 2, 4, 8, 16, 32, 64 repetitions per probe.
 */
#define NUM_REPETITIONS 1

/*
 * The attacker probes with a granularity of 0x10 (16) bytes during one part of
 * one of the BlindSide exploits, since this is the function entry point
 * alignment relevant to the Spectre gadget that they aim to discover.
 *
 * We manually change this number according to what we require of our
 * experiments to perform a realistic evaluation of SpecProbeGuard's
 * security guarantees.
 */
#define SPECTRE_GADGET_PROBE_INTERVAL 16

/*
 * A configurable probing granularity at which the attacker will probe, looking
 * for a 'target gadget' in the kernel, starting at a given location.
 */
#define ADDT_CONFIG_PROBE_GRANULARITY 0x20

/*
 * During one of the other BlindSide exploits, the attacker probes the kernel's
 * heap memory to discover a ROP payload. Since we do not defend the heap
 * against exploitation, we will simulate probing with this granularity still
 * to acquire a representative view of what would happen if we were to defend
 * the heap against these types of attacks.
 */
#define ROP_PAYLOAD_PROBE_GRANULARITY 0x8000

/* For generating (random) addresses for starting and target locations. */
uint64_t get_rand_in_range(uint64_t lower, uint64_t upper){
	uint64_t res;
	res = 0;

	get_random_bytes(&res, sizeof(uint64_t));
	res = (res % (upper - lower)) + lower;

	return res;
}

/*
 * Function for aligning starting/targeted location addresses to an attacker's
 * probing granularity.
 */
void *align_addr(void *loc, uint64_t alignment){
	void *res_loc;
	res_loc = loc;

	/*
	 * Using modulo is very slow, but we do not care about our attacker's
	 * performance yet in this particular part. Only the actual probing matters.
	 */
	if((uint64_t) loc % alignment != 0)
		res_loc = (void *) (((uint64_t) loc + (alignment - 1)) & -alignment);

	return res_loc;
}

/*
 * The dummy function that we train on prior to switching the attack gadget's
 * condition in order to induce speculation on the indirect call it contains.
 */
void train_func(void){
	return;
}

// -- BLINDSIDE SIMULATION: FINDING THE KERNEL IMAGE BASE --

/* Probing granularities used for this portion of the simulation. */
#define KERNEL_BASE_PROBE_INTERVAL_HIGH 0x800000
#define KERNEL_BASE_PROBE_INTERVAL_LOW 0x200000

/* Range in which the kernel image is bound to occur when KASLR is active. */
#define KERNEL_BASE_LOWER_RANGE_ADDR 0xffffffff80000000
#define KERNEL_BASE_UPPER_RANGE_ADDR 0xffffffffc0000000

/*
 * Function that simulates a BlindSide exploit on a stock Linux kernel (i.e.,
 * with standard defences, no state-of-the-art stuff) and coarse-grained KASLR,
 * where the attacker probes the address space in a particular range to discover
 * the kernel image's base. After doing so, further exploitation is enabled.
 */
void blindside_sim_kernel_base_func(void){
	void *starting_loc, *target_loc, *probe_targ_loc;
	int i, j, obj_idx;
	uint8_t target_found;
	uint64_t probe_granularity, num_locs_1, num_locs_2, num_launched_probes;

	starting_loc = NULL;
	target_loc = NULL;
	probe_targ_loc = NULL;

	i = 0;
	j = 0;
	obj_idx = 0;

	target_found = 0;

	probe_granularity = 0;
	num_locs_1 = 0;
	num_locs_2 = 0;
	num_launched_probes = 0;

	/* We set up the simulated BlindSide attack. */
	fp_enabled_offset = sizeof(objs[0].pad) / sizeof(objs[0].pad[0]);

	for(i = 0; i < NUM_OBJS; i++){
		objs[i].fp_enabled = 1;
		objs[i].fp = train_func;
	}

	/*
	 * Initialize the probing object variables. Put the actual targeted
	 * locations in during the attack, calculating them dynamically.
	 */
	objs[TARGET_OBJ].fp_enabled = 0;
	objs[TARGET_OBJ].fp = probe_targ_loc;

	/*
	 * Since this is a simulation, we pre-determine where the kernel image's
	 * base is in memory to know when the attacker was successful.
	 */
	target_loc = (void *) KERNEL_BASE_ADDR;

	/* 
	 * The attacker, in the real exploit, applies 'code region probing' on a
	 * large range of memory in which the kernel image is bound to start.
	 *
	 * This range is: 0xffffffff80000000 - 0xffffffffc0000000.
	 */
	starting_loc = (void *) KERNEL_BASE_LOWER_RANGE_ADDR;

	/*
	 * Initially, the attacker probes with a granularity of 8 MB until one of
	 * their probes hits a mapped page (i.e., one in kernel space). Then, the
	 * attacker goes back to the prior unmapped page that they probed prior to
	 * the hit, and probes at a granularity of 2 MB (since the kernel is
	 * aligned to 2 MB huge pages) until they discover the base.
	 */
	probe_granularity = KERNEL_BASE_PROBE_INTERVAL_HIGH;

	printk("%s [DEBUG]: Kernel base (target) at 0xffffffff%x. Now starting probes at 0xffffffff%x at granularity %ld (0x%x)\n",
				DEVICE_NAME, target_loc, starting_loc, probe_granularity,
				probe_granularity);

	while(probe_targ_loc < (void *) KERNEL_BASE_UPPER_RANGE_ADDR){
		if(target_found == 1)
			break;

		/* Calculate the to-probe location. */
		if(probe_granularity == KERNEL_BASE_PROBE_INTERVAL_HIGH){
			probe_targ_loc = (void *) ((char *) starting_loc + (num_locs_1 *
				probe_granularity));
		}else{
			probe_targ_loc = (void *) ((char *) starting_loc + (num_locs_2 *
				probe_granularity));
		}
		objs[TARGET_OBJ].fp = probe_targ_loc;

		for(i = 0; i < NUM_REPETITIONS; i++){
			/*
			 * This for loop launches *one* speculative probe by first training
			 * the CPU and then inducing speculation on the targeted location.
			 */
			for(j = 0; j < NUM_TOTAL_ITER; j++){
				blindside_func(&objs[obj_idx++]);

				if(obj_idx == NUM_OBJS){
					num_launched_probes++;
					obj_idx = 0;
				}
			}

			printk("%s [DEBUG]: (%ld -- %ld) Probed 0xffffffff%x at step size 0x%x, now at location %d.\n",
				DEVICE_NAME, ktime_get_ns(), num_launched_probes - 1,
				probe_targ_loc, probe_granularity, num_locs_1 + num_locs_2);
		}

		/* Check whether our launched probe(s) hit something interesting. */
		if(probe_targ_loc == target_loc){
			/*
			 * The attacker has found and probed the kernel image's base,
			 * and has successfully executed this part of the exploit.
			 */
			target_found = 1;

			break;
		}else if(probe_targ_loc > target_loc){
			/*
			 * The attacker has hit a mapped page from the kernel somewhere.
			 * Now, they will go back the prior unmapped page and lower the
			 * probing granularity to discover the actual kernel image base.
			 */
			starting_loc = (void *) ((char *) probe_targ_loc -
				KERNEL_BASE_PROBE_INTERVAL_HIGH);
			probe_granularity = KERNEL_BASE_PROBE_INTERVAL_LOW;

			/*
			 * When the attacker finds a code page, they skip the address
			 * aligned to 8 MB prior to the mapped code page. Namely,
			 * probing this address again, but at a lower granularity, will
			 * of course not help the attacker uncover the kernel base.
			 */
			printk("%s [DEBUG]: Found code page. Switching from 0x%x to 0x%x probe granularity.\n",
				DEVICE_NAME, KERNEL_BASE_PROBE_INTERVAL_HIGH,
				KERNEL_BASE_PROBE_INTERVAL_LOW);
			printk("%s [DEBUG]: Re-commencing probing from 0xffffffff%x onward.\n",
				DEVICE_NAME, starting_loc);

			break;
		}

		if(probe_granularity == KERNEL_BASE_PROBE_INTERVAL_HIGH){
			num_locs_1++;
		}else{
			num_locs_2++;
		}
	}

	/*
	 * Dump the statistics about this simulated attack, e.g., how many probes
	 * the attacker launched in total, how many addresses they tried, and so on.
	 */
	printk(KERN_INFO "%s [INFO]: Found kernel base at 0xffffffff%x, when really at 0xffffffff%x, after probing %ld locations with %ld total probes (%ld for each location).\n",
		DEVICE_NAME, probe_targ_loc, KERNEL_BASE_ADDR, num_locs_1 + num_locs_2,
		num_launched_probes, NUM_REPETITIONS);
}


// -- BLINDSIDE SIMULATION: GENERAL CONFIGURABLE EXPLOIT PROBING --

/*
 * Function that simulates a BlindSide exploit on a stock kernel, where the
 * attacker, due to the absence of state-of-the-art defences against code reuse
 * and speculative execution attacks, knows the location of their desired gadget
 * beforehand (by virtue of knowledge of the kernel image's base address, which
 * is assumed as well in order to render this attack practically possible).
 *
 * Because the attacker knows the location of their target gadget in the stock
 * kernel, we assume they will probe this location directly. However, we do
 * also assume that the attacker does not know about the booby traps embedded in
 * the kernel, causing the target gadget to be misaligned. The attacker, as a
 * result, must still probe at a low granularity to discover the actual location
 * in our instrumented kernel, and may thus still trigger booby traps.
 */
void blindside_sim_gadget_func(void){
	void *starting_loc, *target_loc, *probe_targ_loc;
	int i, j, obj_idx;
	uint8_t target_found;
	uint64_t probe_granularity, num_locs, num_launched_probes;

	starting_loc = NULL;
	target_loc = NULL;
	probe_targ_loc = NULL;

	i = 0;
	j = 0;
	obj_idx = 0;

	target_found = 0;

	probe_granularity = 0;
	num_locs = 0;
	num_launched_probes = 0;

	/*
	 * The attacker will probe their gadget at our pre-configured granularity.
	 * Configure a probing granularity here that seems realistic and suitable
	 * for a situation where an attacker probes to discover their misaligned
	 * target gadget, for which the location was known in the stock kernel.
	 */
	probe_granularity = SPECTRE_GADGET_PROBE_INTERVAL;

	/*
	 * We must determine where the gadget is in the kernel's image that the
	 * attacker targets during their attack. Since this is a simulation of no
	 * specific exploit, we may choose any location in the kernel.
	 */
	do{
		/* Pick a random target location in the stock kernel's .text section. */
		target_loc = (void *) get_rand_in_range(KERNEL_STOCK_TEXT_SECTION_START_ADDR,
			KERNEL_STOCK_TEXT_SECTION_END_ADDR);

		/*
		 * The attacker commences probing at the location they think is where
		 * their desired gadget is (and where it would be in a stock kernel),
		 * aligned to the configured probing granularity by rounding up.
		 */
		starting_loc = align_addr(target_loc, probe_granularity);;

		/*
		 * We shift the target_loc to account for the misalignment caused by the
		 * embedded booby traps (of which the attacker knows not how many there
		 * are, their size, etc.), and align it again to the probing
		 * granularity. We approximate this all, since this remains a
		 * simulation, yet this should be sufficiently representative.
		 */
		target_loc = (void *) ((char *) target_loc +
			((KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR -
				KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR) -
				(KERNEL_STOCK_TEXT_SECTION_END_ADDR -
					KERNEL_STOCK_TEXT_SECTION_START_ADDR)));
		target_loc = align_addr(target_loc, probe_granularity);
	}while(!(target_loc >= (void *) KERNEL_BASE_ADDR) && !(target_loc <=
		(void *) (KERNEL_BASE_ADDR +
			(KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR -
				KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR))));

	/* We set up the simulated BlindSide attack. */
	fp_enabled_offset = sizeof(objs[0].pad) / sizeof(objs[0].pad[0]);

	for(i = 0; i < NUM_OBJS; i++){
		objs[i].fp_enabled = 1;
		objs[i].fp = train_func;
	}

	/*
	 * Initialize the probing object variables. Put the actual targeted
	 * locations in during the attack, calculating them dynamically.
	 */
	objs[TARGET_OBJ].fp_enabled = 0;
	objs[TARGET_OBJ].fp = probe_targ_loc;

	printk("%s [DEBUG]: Selected address (target) at 0xffffffff%x. Now starting probes at 0xffffffff%x at granularity %ld (0x%x)\n",
				DEVICE_NAME, target_loc, starting_loc, probe_granularity,
				probe_granularity);

	while(probe_targ_loc < (void *) ((char *) starting_loc +
							(KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR -
								KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR))){
		if(target_found == 1)
			break;

		/* Calculate the address the attacker wants to probe. */
		probe_targ_loc = (void *) ((char *) starting_loc + (num_locs *
			probe_granularity));
		objs[TARGET_OBJ].fp = probe_targ_loc;

		for(i = 0; i < NUM_REPETITIONS; i++){
			/*
			 * This for loop launches *one* speculative probe by first training
			 * the CPU and then inducing speculation on the targeted location.
			 */
			for(j = 0; j < NUM_TOTAL_ITER; j++){
				blindside_func(&objs[obj_idx++]);

				if(obj_idx == NUM_OBJS){
					num_launched_probes++;
					obj_idx = 0;
				}
			}

			printk("%s [DEBUG]: (%ld -- %ld) Probed 0xffffffff%x at step size 0x%x, now at location %d.\n",
				DEVICE_NAME, ktime_get_ns(), num_launched_probes - 1,
				probe_targ_loc, probe_granularity, num_locs);
		}

		/* Check whether our launched probe(s) hit something interesting. */
		if(probe_targ_loc == target_loc){
			/*
			 * The attacker has probed and found the 'target gadget' in the
			 * kernel. Hence, the attack was successful.
			 */
			target_found = 1;
			break;
		}

		num_locs++;
	}

	/*
	 * Dump the statistics about this simulated attack, e.g., how many probes
	 * the attacker launched in total, how many addresses they tried, and so on.
	 */
	if(target_found == 1){
		printk(KERN_INFO "%s [INFO]: Starting from 0xfffffff%x, found the target gadget at 0xffffffff%x, when really at 0xffffffff%x, after probing %ld locations with %ld probes (%ld for each location).\n",
			DEVICE_NAME, starting_loc, probe_targ_loc, target_loc, num_locs,
			num_launched_probes, NUM_REPETITIONS);
	}else{
		printk(KERN_INFO "%s [INFO]: Starting from 0xfffffff%x, did not find the target gadget at 0xffffffff%x after probing %ld locations with %ld probes (%ld for each location).\n",
			DEVICE_NAME, starting_loc, target_loc, num_locs,
			num_launched_probes, NUM_REPETITIONS);
	}
}

// -- BLINDSIDE SIMULATION: ADVANCED GENERAL CONFIGURABLE EXPLOIT PROBING --

/*
 * Function that simulates a BlindSide exploit on a kernel with additional
 * state-of-the-art defences against code-reuse and speculative execution
 * attacks, where we simply probe from a randomised start location (to simulate
 * the kernel's internals also being randomised, while our simulation kernel is
 * in reality not) at a configurable granularity to discover a target at a
 * randomised location. This particular function simulates an attack that, in
 * general, represents the majority of the existing BlindSide's shown exploits.
 *
 * It is assumed the attacker has already determined the location of the kernel
 * image's base, and that this is the only information they have been able to
 * acquire (due to the presence of more advanced defences). We randomise the
 * starting location still to account for internal randomisation of the kernel
 * image, as probing from the base would cause unfair evaluations in this case.
 */
void blindside_sim_adv_gadget_func(unsigned long param_probe_granularity){
	void *starting_loc, *target_loc, *probe_targ_loc;
	int i, j, obj_idx;
	uint8_t target_found;
	uint64_t probe_granularity, num_locs, num_launched_probes;

	starting_loc = NULL;
	target_loc = NULL;
	probe_targ_loc = NULL;

	i = 0;
	j = 0;
	obj_idx = 0;

	target_found = 0;

	probe_granularity = 0;
	num_locs = 0;
	num_launched_probes = 0;

	/* The attacker will probe at our pre-configured granularity. */
	probe_granularity = param_probe_granularity;

	/*
	 * We must determine where the gadget is in kernel's image that the attacker
	 * targets during their attack. Since this is a simulation of no exploit in
	 * particular, we may choose any location in the kernel.
	 *
	 * Currently, we select a random location in the kernel to be where our
	 * attacker's target is. This should also give us a fairer representation of
	 * an attack, and a realistic attack scenario.
	 *
	 * Lastly, if the target location is not aligned to the probing granularity,
	 * align it to the next boundary by rounding up. In case the generated
	 * address goes out of range, try again.
	 */
	do{
		target_loc = (void *) get_rand_in_range(
			(uint64_t) KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR,
			(uint64_t) KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR);
		target_loc = align_addr(target_loc, probe_granularity);
	}while(!(target_loc >= (void *) KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR)
		&& !(target_loc <= (void *) (KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR)));

	/*
	 * For our starting location, we select a random address in the kernel's
	 * image. This should more accurately represent how an attacker might probe
	 * the kernel when there are state-of-the-art defences that randomise the
	 * kernel image's layout (otherwise, the attacker might keep hitting the
	 * same booby traps, making sure this simulation is not realistic).
	 *
	 * However, we do need to ensure that the attacker's starting location
	 * occurs before the target in the range. We take this into account.
	 * 
	 * Again, if the starting location is not aligned to the probing
	 * granularity, align it to the next boundary by rounding up.
	 */
	do{
		starting_loc = (void *) get_rand_in_range(
			(uint64_t) KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR,
			(uint64_t) target_loc);
		starting_loc = align_addr(starting_loc, probe_granularity);
	}while(!(starting_loc >= (void *) KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR)
		&& !(starting_loc <= target_loc));

	probe_targ_loc = starting_loc;

	/* We set up the simulated BlindSide attack. */
	fp_enabled_offset = sizeof(objs[0].pad) / sizeof(objs[0].pad[0]);

	for(i = 0; i < NUM_OBJS; i++){
		objs[i].fp_enabled = 1;
		objs[i].fp = train_func;
	}

	/*
	 * Initialize the probing object variables. Put the actual targeted
	 * locations in during the attack, calculating them dynamically.
	 */
	objs[TARGET_OBJ].fp_enabled = 0;
	objs[TARGET_OBJ].fp = probe_targ_loc;

	printk("%s [DEBUG]: Selected address (target) at 0xffffffff%x. Now starting probes at 0xffffffff%x at granularity %ld (0x%x)\n",
				DEVICE_NAME, target_loc, starting_loc, probe_granularity,
				probe_granularity);

	while(probe_targ_loc < (void *) KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR){
		if(target_found == 1)
			break;

		/* Calculate the address the attacker wants to probe. */
		probe_targ_loc = (void *) ((char *) starting_loc + (num_locs *
			probe_granularity));
		objs[TARGET_OBJ].fp = probe_targ_loc;

		for(i = 0; i < NUM_REPETITIONS; i++){
			/*
			 * This for loop launches *one* speculative probe by first training
			 * the CPU and then inducing speculation on the targeted location.
			 */
			for(j = 0; j < NUM_TOTAL_ITER; j++){
				/* Helps break LLVM-CFI. */
				// for(k = 0; k < NUM_OBJS; k++)
					// objs[0].fp();

				blindside_func(&objs[obj_idx++]);

				if(obj_idx == NUM_OBJS){
					num_launched_probes++;
					obj_idx = 0;
				}
			}

			printk("%s [DEBUG]: (%ld -- probe %ld) Probed 0xffffffff%x at step size 0x%x, now at location %d. Started from 0xffffffff%x, target at 0xffffffff%x.\n",
				DEVICE_NAME, ktime_get_ns(), num_launched_probes - 1,
				probe_targ_loc, probe_granularity, num_locs, starting_loc,
				target_loc);
		}

		/* Check whether our launched probe(s) hit something interesting. */
		if(probe_targ_loc == target_loc){
			/*
			 * The attacker has probed and found the 'target gadget' in the
			 * kernel. Hence, the attack was successful.
			 */
			target_found = 1;
			break;
		}

		num_locs++;
	}

	/*
	 * Dump the statistics about this simulated attack, e.g., how many probes
	 * the attacker launched in total, how many addresses they tried, and so on.
	 */
	if(target_found == 1){
		printk(KERN_INFO "%s [INFO]: Starting from 0xffffffff%x, found the target gadget at 0xffffffff%x, when really at 0xffffffff%x, after probing %ld locations with %ld probes (%ld for each location).\n",
			DEVICE_NAME, starting_loc, probe_targ_loc, target_loc, num_locs,
			num_launched_probes, NUM_REPETITIONS);
	}else{
		printk(KERN_INFO "%s [INFO]: Starting from 0xffffffff%x, did not find the target gadget at 0xffffffff%x after probing %ld locations with %ld probes (%ld for each location).\n",
			DEVICE_NAME, starting_loc, target_loc, num_locs,
			num_launched_probes, NUM_REPETITIONS);
	}
}

/*
 * Function that does exactly the same as the above (advanced exploitation,
 * probing for a gadget), and the same assumptions regarding the kernel's
 * randomisation and such hold, but now the probing scheme is random. Rather
 * than linearly probing from a starting location towards the exploitable
 * target, the attacker probes randomly until they hit their target.
 */
void blindside_sim_adv_gadget_func_rand(void){
	void *starting_loc, *target_loc, *probe_targ_loc;
	int i, j, k, obj_idx;
	uint8_t target_found;
	uint64_t probe_granularity, num_locs, num_launched_probes;

	starting_loc = NULL;
	target_loc = NULL;
	probe_targ_loc = NULL;

	i = 0;
	j = 0;
	k = 0;
	obj_idx = 0;

	target_found = 0;

	probe_granularity = 0;
	num_locs = 0;
	num_launched_probes = 0;

	/* The attacker will probe at our pre-configured granularity. */
	probe_granularity = SPECTRE_GADGET_PROBE_INTERVAL;

	/*
	 * We must determine where the gadget is in kernel's image that the attacker
	 * targets during their attack. Since this is a simulation of no exploit in
	 * particular, we may choose any location in the kernel.
	 *
	 * Currently, we select a random location in the kernel to be where our
	 * attacker's target is. This should also give us a fairer representation of
	 * an attack, and a realistic attack scenario.
	 *
	 * Lastly, if the target location is not aligned to the probing granularity,
	 * align it to the next boundary by rounding up. In case the generated
	 * address goes out of range, try again.
	 */
	do{
		target_loc = (void *) get_rand_in_range(
			(uint64_t) KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR,
			(uint64_t) KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR);
	}while(!(target_loc >= (void *) KERNEL_BASE_ADDR) && !(target_loc <=
		(void *) (KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR)));

	/* We set up the simulated BlindSide attack. */
	fp_enabled_offset = sizeof(objs[0].pad) / sizeof(objs[0].pad[0]);

	for(i = 0; i < NUM_OBJS; i++){
		objs[i].fp_enabled = 1;
		objs[i].fp = train_func;
	}

	/*
	 * Initialize the probing object variables. Put the actual targeted
	 * locations in during the attack, calculating them dynamically.
	 */
	objs[TARGET_OBJ].fp_enabled = 0;
	objs[TARGET_OBJ].fp = probe_targ_loc;

	printk("%s [DEBUG]: Selected address (target) at 0xffffffff%x. Now starting probes at random at granularity %ld (0x%x)\n",
				DEVICE_NAME, target_loc, probe_granularity,
				probe_granularity);

	/*
	 * In this exploit simulation, we probe randomly (at a granularity of 16
	 * bytes, i.e., that is our alignment). Hence, we pick our targets at
	 * random, and see what happens.
	 */
	while(target_found == 0){
		/* Pick a random address in the kernel image's .text section. */
		do{
			probe_targ_loc = (void *) get_rand_in_range(
				(uint64_t) KERNEL_INSTRUMENTED_TEXT_SECTION_START_ADDR,
				(uint64_t) KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR);
			// probe_targ_loc = align_addr(probe_targ_loc, probe_granularity);
		}while(!(probe_targ_loc >= (void *) KERNEL_BASE_ADDR) && !(probe_targ_loc <=
			(void *) (KERNEL_INSTRUMENTED_TEXT_SECTION_END_ADDR)));

		objs[TARGET_OBJ].fp = probe_targ_loc;

		for(i = 0; i < NUM_REPETITIONS; i++){
			/*
			 * This for loop launches *one* speculative probe by first training
			 * the CPU and then inducing speculation on the targeted location.
			 */
			for(j = 0; j < NUM_TOTAL_ITER; j++){
				blindside_func(&objs[obj_idx++]);

				if(obj_idx == NUM_OBJS){
					num_launched_probes++;
					obj_idx = 0;
				}
			}
			
			if(k % 100 == 0){
				printk("%s [DEBUG]: (%ld -- probe %ld) Probed 0xffffffff%x at step size 0x%x, now at location %d. Started at random, target at 0xffffffff%x.\n",
					DEVICE_NAME, ktime_get_ns(), num_launched_probes - 1,
					probe_targ_loc, probe_granularity, num_locs, target_loc);
			}

			k += 1;
		}

		/* Check whether our launched probe(s) hit something interesting. */
		if(probe_targ_loc == target_loc){
			/*
			 * The attacker has probed and found the 'target gadget' in the
			 * kernel. Hence, the attack was successful.
			 */
			target_found = 1;
			break;
		}

		num_locs++;
	}

	/*
	 * Dump the statistics about this simulated attack, e.g., how many probes
	 * the attacker launched in total, how many addresses they tried, and so on.
	 */
	if(target_found == 1){
		printk(KERN_INFO "%s [INFO]: Starting at random, found the target gadget at 0xffffffff%x, when really at 0xffffffff%x, after probing %ld locations with %ld probes (%ld for each location).\n",
			DEVICE_NAME, probe_targ_loc, target_loc, num_locs,
			num_launched_probes, NUM_REPETITIONS);
	}else{
		printk(KERN_INFO "%s [INFO]: Starting at random, did not find the target gadget at 0xffffffff%x after probing %ld locations with %ld probes (%ld for each location).\n",
			DEVICE_NAME, target_loc, num_locs,
			num_launched_probes, NUM_REPETITIONS);
	}
}

// -- BLINDSIDE SIMULATION: BOOBY TRAP SENSITIVITY SIMULATION --

/*
 * Function that probes a known booby trap location at a specific part of the
 * booby trap gadget, whereby we may determine the sensitivity of the trap.
 */
void blindside_sim_trap_sens_sim(void){
	void *probe_targ_loc;
	int i, j, obj_idx;
	uint64_t num_launched_probes;

	i = 0;
	j = 0;
	obj_idx = 0;

	num_launched_probes = 0;

	/* Choose the to-probe part of a known booby trap location. */
	probe_targ_loc = (void *) 0xffffffff8100065a;

	/* We set up the simulated BlindSide attack. */
	fp_enabled_offset = sizeof(objs[0].pad) / sizeof(objs[0].pad[0]);

	for(i = 0; i < NUM_OBJS; i++){
		objs[i].fp_enabled = 1;
		objs[i].fp = train_func;
	}

	/*
	 * Set the checked condition to 0 (false) to enable the incorrect speculative
	 * execution of the branch, after which the function pointer, which is now set
	 * to the target location containing the target code, will execute speculatively.
	 */
	objs[TARGET_OBJ].fp_enabled = 0;
	objs[TARGET_OBJ].fp = probe_targ_loc;

	for(i = 0; i < 10000; i++){
		/*
		 * Perform the actual exploit, training the CPU first and finally accessing
		 * the target location to speculatively execute the previously inserted code.
		 */
		for(j = 0; j < NUM_TOTAL_ITER; j++){
			/* Execute the actual BlindSide attack, probing the target after having trained. */
			blindside_func(&objs[obj_idx++]);

			if(obj_idx == NUM_OBJS){
				num_launched_probes++;
				obj_idx = 0;
			}
		}
	}

	printk(KERN_INFO "%s [INFO]: Probed 0xffffffff%x with %ld probes.\n",
		DEVICE_NAME, probe_targ_loc, num_launched_probes);

}

// -- DEVICE AND IOCTL OPERATIONS --

/*
 * This function is called whenever a process attempts to execute an ioctl on
 * the associated device file.
 */
static long device_ioctl(struct file *file, unsigned int ioctl_num,
													unsigned long ioctl_param){
	long ret_val;
	ret_val = 0;

	switch(ioctl_num){
		case IOCTL_SPG_EVAL_KM_NOP:
			break;

		case IOCTL_SPG_EVAL_KM_KERNEL_BASE_ATT:
			printk(KERN_INFO "%s [INFO]: Simulating probing exploit to discover the kernel base address.\n",
				DEVICE_NAME);
			blindside_sim_kernel_base_func();
			printk(KERN_INFO "%s [INFO]: Finished simulation.\n", DEVICE_NAME);

			break;

		case IOCTL_SPG_EVAL_KM_GADGET_ATT:
			printk(KERN_INFO "%s [INFO]: Simulating probing exploit to discover a target gadget in the kernel's image (stock kernel).\n",
				DEVICE_NAME);
			blindside_sim_gadget_func();
			printk(KERN_INFO "%s [INFO]: Finished simulation.\n", DEVICE_NAME);

			break;

		case IOCTL_SPG_EVAL_KM_ADV_GADGET_ATT:
			printk(KERN_INFO "%s [INFO]: Simulating probing exploit to discover a target gadget in the kernel's image (kernel with advanced, state-of-the-art defences), probing linearly.\n",
				DEVICE_NAME);
			blindside_sim_adv_gadget_func(ioctl_param);
			printk(KERN_INFO "%s [INFO]: Finished simulation.\n", DEVICE_NAME);

			break;

		case IOCTL_SPG_EVAL_KM_ADV_GADGET_ATT_RAND:
			printk(KERN_INFO "%s [INFO]: Simulating probing exploit to discover a target gadget in the kernel's image (kernel with advanced, state-of-the-art defences), probing randomly.\n",
				DEVICE_NAME);
			blindside_sim_adv_gadget_func_rand();
			printk(KERN_INFO "%s [INFO]: Finished simulation.\n", DEVICE_NAME);

			break;

		case IOCTL_SPG_EVAL_KM_TRAP_SENS_SIM:
			printk(KERN_INFO "%s [INFO]: Simulating attacks to determine the sensitivity of the embedded booby traps.\n",
				DEVICE_NAME);
			blindside_sim_trap_sens_sim();
			printk(KERN_INFO "%s [INFO]: Finished simulation.\n", DEVICE_NAME);

			break;

		default:
			printk(KERN_INFO "%s [ERROR]: No such command (%d).", DEVICE_NAME,
				ioctl_num);
			ret_val = -EINVAL;
	}

	return ret_val;
}

static int device_open(struct inode *inode, struct file *file){
	return 0;
}

static int device_release(struct inode *inode, struct file *file){
	return 0;
}

// -- DEVICE/IOCTL REQUIRED --

/*
 * Struct that holds the functions to be called when a process interacts with
 * the created device. Cannot be local.
 */
struct file_operations file_ops = {
	.unlocked_ioctl = device_ioctl,
	.open = device_open,
	.release = device_release,
};

// -- MODULE --

int init_module(void){
	int ret_val;
	ret_val = 0;

	printk(KERN_INFO "%s [INFO]: Loading kernel module for SpecProbeGuard evaluation.", DEVICE_NAME);

	/* Attempt to register the character device. */
	ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &file_ops);

	if(ret_val < 0){
		printk(KERN_INFO "%s [ERROR]: Failed to register character device (ret: %d). Exiting.\n", DEVICE_NAME, ret_val);
		
		ret_val = -1;
		goto out;
	}

	printk(KERN_INFO "%s [SUCCESS]: Registered character device.\n", DEVICE_NAME);
	printk(KERN_INFO "%s [INFO]: Major device number of this device is %d. Create a device file to access the device driver -- use: mknod %s c %d 0.\n", DEVICE_NAME, MAJOR_NUM, DEVICE_FILE_NAME, MAJOR_NUM);

out:
	return ret_val;
}

void cleanup_module(void){
	/* Attempt to unregister the previously registered device. */
	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);

	printk(KERN_INFO "%s [SUCCESS]: Attempted to unregister character device. Exiting.\n", DEVICE_NAME);
}