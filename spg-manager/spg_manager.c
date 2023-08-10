/*
 * spg_manager.c -- A kernel module that coordinates and controls
 * SpecProbeGuard, a defence against speculative probing (or, BlindSide-based)
 * Spectre-type attacks, and its various 'phases' in practice. This module,
 * together with the CodeGen-level and IR-level LLVM passes, make up the defence
 * that in essence facilitates the detection, tracing, and mitigation of
 * speculative probing attacks by means of booby trap code gadgets embedded in
 * the kernel, a cache covert channel, and reactive code transformation. Through
 * the application of the latter in the kernel, we mitigate any speculative
 * probing attacks we detect on demand, applying costly mitigations if and only
 * if an attack really occurred, and thereby ensure the lowest required incurred
 * performance penalty for the kernel.
 *
 * This module, in particular, guides the control flow of the defence, and
 * invokes each of its phases after the detection of a speculative probe. It
 * sets up performance counters, checks the covert channel, and invokes reactive
 * code transformation using the static keys, all when necessary.
 *
 * SPECULATIVE PROBE DETECTION:
 * The detection phase of the defence is implemented by the instrumentation of
 * the kernel source code through the CodeGen-level LLVM pass with 'booby trap'
 * code gadgets. This means that we append a trap consisting of several ASM
 * instructions to every RET instruction that closes a function in the kernel;
 * this, together with allowing for probe detection, also ensures our trap (in
 * principle) cannot be tripped by any functionally legal control flow.
 *
 * In particular, these trap gadgets firstly contain a NOP sled that increases
 * the chances of an attacker hitting our trap while probing. Then, we use a
 * MOV instruction to load the address of a location in memory that corresponds
 * to an antry in our covert channel -- where every entry matches a particular
 * ID of a specific indirect call site in the kernel. This address is
 * pre-calculated as a result of the indirect call site (attack gadget)
 * instrumentation, realised by the IR-level pass, where upon the (speculative)
 * execution of an indirect call, we record its ID and store its
 * corresponding entry in our cache covert channel in a per-CPU variable. Thus,
 * the booby trap acquires the address of the entry matching the attack gadget
 * used to launch the detected probe, and subsequently executes a PREFETCHT1
 * instruction to prefetch this entry's memory. It, thereby, discloses the ID
 * of the attack gadget the attacker used to construct their probing primitive,
 * which we may discover through the use of our cache covert channel.
 *
 * The execution of a PREFETCHT1 instruction alerts us to the presence of a
 * speculative probe. Namely, we set up a series of perf performance counters in
 * this kernel module that, for each CPU in the system, track PREFETCHT1 events
 * that occur (both on the architectural path, and on the speculative path).
 *
 * This detection scheme works because PREFETCHT1 and PREFETCHT2 instructions do
 * not occur naturally in the kernel, which is why we select one of these to
 * serve as our 'alert'; we are guaranteed that an attack has occured, since we
 * know that our trap is beyond benign control flow, and such an instruction
 * does not occur anywhere else. It is important to note that, in principle,
 * any instruction can be used to do this, as long as one can reliably ascertain
 * that the detected 'probe' was legitimate.
 *
 * ATTACK SOURCE TRACING:
 * Once a booby trap gadget was executed by a speculative probe, this defence
 * manager kernel module picks up the hardware event the PREFETCHT1 generated,
 * and diverts control flow to an NMI handler. Here, we check our the memory
 * buffer of our cache covert channel by utilizing a FLUSH+RELOAD attack, to
 * determine whether any entries were cached by a speculative access.
 *
 * When we discover that one of the entries was, indeed, cached by the execution
 * of a booby trap, we know that a probe has legitimately caused a booby trap
 * to be triggered, and that the indirect call site (attack gadget)
 * corresponding to the cached entry was used to launch it. From there, the
 * kernel module moves to apply reactive code transformation to mitigate the
 * attack, entering the last phase of SpecProbeGuard's operation.
 *
 * REACTIVE CODE TRANSFORMATION:
 * The reactive code transformation phase of this defence similarly concerns the
 * instrumentation of kernel source code; specifically, we focus on
 * instrumenting indirect calls, as they enable attackers to launch the type of
 * speculative probing attacks that we seek to mitigate. To do so, we insert
 * static key branches that can be switched by enabling or disabling their
 * associated static key(s), resulting in code from either branch being patched
 * in, on-the-fly, by the kernel.
 *
 * At this time, we use the following two branches: the 'then' branch (disabled
 * by default), which contains our selected method to stop attacker-induced 
 * speculation -- an LFENCE instruction; and the 'else' branch (enabled by
 * default), which facilitates the speculative probe detection and attack source
 * tracing phases by recording the ID of the indirect call that was executed
 * (speculatively) most recently and calculating the address of an entry in our
 * covert channel buffer that matches it, thereby allowing a booby trap to
 * disclose the source of the probe that launched it and us to trace it using
 * our covert channel.
 *
 * Once a detected probe's source was ascertained during the attack source
 * tracing phase, the NMI handler in the defence manager kernel module activates
 * its corresponding static key. This results in the default (detection/tracing)
 * branch being patched out, and the mitigation branch with the LFENCE
 * instruction being patched in; as this instruction disrupts speculation
 * sufficiently, the gadget can no longer be speculatived executed.
 * Consequently, once the attacker's gadget is dismantled, and with it their
 * speculative probing primitive, they are no longer able to use this attack
 * gadget to launch speculative probes. The detected attack was mitigated.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cpufeature.h>

#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#include <linux/unistd.h>

#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/delay.h>

#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>

// -- INCLUDED CUSTOM FILES --

#include "spg_device_essentials.h"
#include "path/to/include/spg_header.h"

// -- MODULE DEFINITIONS --

#define DRIV_NAME "SpecProbeGuard Defence Manager"

#define MOD_AUTHOR "daveq"
#define MOD_DESC "A kernel module that manages the defensive measures against speculative probing Spectre-type attacks."
#define MOD_VERSION "0.1"
#define MOD_LICENSE "GPL"

MODULE_LICENSE(MOD_LICENSE);
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_DESCRIPTION(MOD_DESC);
MODULE_VERSION(MOD_VERSION);

#define DEVICE_NAME "spg_manager"

// -- SPECULATIVE PROBE MITIGATION (STATIC KEY) ESSENTIALS --

#define NUM_STATIC_KEYS REQ_STATIC_KEY_NUM

#define STATIC_KEY_ENABLED 			 1
#define STATIC_KEY_DISABLED 		 0
#define STATIC_KEY_NULL 			-1
#define STATIC_KEY_STATE_INVALID 	-2

/*
 * This wrapper might be superfluous, so dump it if that becomes obvious once
 * we start implementing the final version of this defence.
 */
struct spg_key_wrapper{
	int key_state;

	/*
	 * Static keys in the kernel are, by default, wrapped in either of two
	 * structs (i.e., static_key_true, static_key_false) for 'typing'. We
	 * wrap our keys additionally to keep track of their state more easily.
	 */
	struct static_key_false *key;

	/*
	 * Counter for number of key activations. Only useful for performance
	 * evaluation with regards to false positives.
	 */
	int num_activations;
};

/* Array of defined keys, wrapped in our own wrapper structs. Remember that we
 * can declare/define keys in arrays from the start as well, which might render
 * this unnecessary.
 */
struct spg_key_wrapper mitigation_static_keys[NUM_STATIC_KEYS];

// -- SPECULATIVE PROBE DETECTION AND HANDLING ESSENTIALS --

/*
 * An error value for setting up the kernel counters; easy to recognise for
 * this module.
 */
#define MISC_ERR_VAL -168

/* Configuration for the SW_PREFETCH event(s); descriptor with umask. */
#define PREFETCH_T1_T2_EVENT_DESC 0x432

/*
 * Struct for perf_event event counting. Configure the sample_period or
 * sample_freq to convert this standard 'counting' counter to a 'sampling'
 * counter, and vice-versa.
 *
 * Check the documentation (which can be found at:
 * man7.org/linux/man-pages/man2/perf_event_open.2.html) for more information.
 */
static struct perf_event_attr spec_probe_perf_event_attr = {
	.type           = PERF_TYPE_RAW,
	.size           = sizeof(struct perf_event_attr),
	.config         = PREFETCH_T1_T2_EVENT_DESC,
	.sample_period  = 1,
	.pinned         = 1,
	.exclude_user   = 1,
};

/* Per-CPU struct that enables the detection of prefetch events using perf. */
static DEFINE_PER_CPU(struct perf_event *, spec_probe_perf_event);

/*
 * Per-CPU counter for the number of prefetch events that were handled in
 * total. Not to be confused with the per-CPU counter for determining when
 * to activate mitigations or not.
 */
static DEFINE_PER_CPU(uint64_t, spec_probe_detected_cnt);

#define FORCE_INLINE __attribute__ ((always_inline)) static inline

// -- STATIC KEY MANAGEMENT --

FORCE_INLINE int switch_static_key_state(int key_state, struct spg_key_wrapper
		*key_wrapper){
	int ret_val;
	ret_val = 0;

	if(key_wrapper == NULL || key_wrapper->key == NULL){
		ret_val = STATIC_KEY_NULL;
		goto out;
	}

	if(key_state == STATIC_KEY_DISABLED){
		if(key_wrapper->key_state == STATIC_KEY_DISABLED)
			goto out;

		/*
		 * Disable the given key, ensuring its related mitigation code in the
		 * kernel becomes INACTIVE.
		 */
		static_branch_disable(key_wrapper->key);
		key_wrapper->key_state = STATIC_KEY_DISABLED;
	}else if(key_state == STATIC_KEY_ENABLED){
		if(key_wrapper->key_state == STATIC_KEY_ENABLED)
			goto out;

		/*
		 * Enable the given key, ensuring its related mitigation code in the
		 * kernel becomes ACTIVE.
		 */
		static_branch_enable(key_wrapper->key);
		key_wrapper->key_state = STATIC_KEY_ENABLED;
	}else{
		ret_val = STATIC_KEY_STATE_INVALID;
	}

out:
	return ret_val;
}

int switch_static_key_state_all(int key_state){
	int ret_val;
	int i;

	ret_val = 0;
	i = 0;

	for(i = 0; i < REQ_STATIC_KEY_NUM; i++){
		ret_val = switch_static_key_state(key_state,
			&mitigation_static_keys[i]);
		if(ret_val < 0)
			goto out;
	}

out:
	return ret_val;
}

// -- STATIC KEY INITIALISATION AND DESTRUCTION --

int exit_static_keys(void){
	int ret_val, i;
	ret_val = 0;
	i = 0;

	/*
	 * To ensure no branches are left active unnecessarily, attempt to disable
	 * all static keys on our exit.
	 */
	for(i = 0; i < NUM_STATIC_KEYS; i++){
		ret_val = switch_static_key_state(STATIC_KEY_DISABLED,
			&mitigation_static_keys[i]);
		if(ret_val < 0){
			printk(KERN_INFO "%s [ERROR]: Failed to disable static key (%d).",
				DEVICE_NAME, i);
			break;
		}
	}

	return ret_val;
}

int init_static_keys(void){
	int ret_val, i;
	ret_val = 0;

	/*
	 * Change or ditch the wrappers and initialisations of them entirely later
	 * if proven unncessary.
	 */
	for(i = 0; i < NUM_STATIC_KEYS; i++){
		mitigation_static_keys[i].key_state = STATIC_KEY_DISABLED;
		mitigation_static_keys[i].key = &(spg_static_keys[i]);
		mitigation_static_keys[i].num_activations = 0;
	}

	return ret_val;
}

// -- SPECULATIVE PROBE DEBUGGING AND EVALUATION --

/*
 * A function that can only be called by a user to check what the current status
 * of the kernel counters are. Only useful for debugging and evaluation.
 */
void spec_probe_counter_status_print(void){
	unsigned int cpu;
	u64 prefetch_handled_total_cnt, prefetch_detected_total_cnt;
	u64 enabled, running;
	
	int i;
	int64_t time;
	
	cpu = get_cpu();
	put_cpu();

	prefetch_handled_total_cnt = 0;
	prefetch_detected_total_cnt = 0;
	
	enabled = 0;
	running = 0;

	/*
	 * Disable preemption, since we are also accessing and working with
	 * variables on the other CPUs in the system.
	 */
	preempt_disable();

	/*
	 * For each online CPU, determine the handled and explicitly counted
	 * prefetch instructions and count up a total.
	 */
	for_each_online_cpu(cpu){
		printk(KERN_INFO "%s [INFO]: For CPU %d: handled %d, counted %lld.\n",
			DEVICE_NAME, cpu, per_cpu(spec_probe_detected_cnt, cpu),
			perf_event_read_value(per_cpu(spec_probe_perf_event, cpu),
				&enabled, &running));
		prefetch_handled_total_cnt += per_cpu(spec_probe_detected_cnt, cpu);
		prefetch_detected_total_cnt += perf_event_read_value(per_cpu(
			spec_probe_perf_event, cpu), &enabled, &running);
	}
	
	printk(KERN_INFO "%s [INFO]: Over all CPUs (%ld): handled %lld, counted %lld.",
		DEVICE_NAME, ktime_get_ns(), prefetch_handled_total_cnt,
		prefetch_detected_total_cnt);

	for(i = 0; i < NUM_STATIC_KEYS; i++){
		if(mitigation_static_keys[i].num_activations > 0)
			printk(KERN_INFO "%s [DEBUG]: Key %d was activated %d times.\n",
				DEVICE_NAME, i, mitigation_static_keys[i].num_activations);
	}

	preempt_enable();
}

// -- SPECULATIVE PROBE HANDLER AND MITIGATION MANAGER --

#define FLUSH_RELOAD_TIMING_THRESHOLD 65 // Upped from 50 to 65. Should help.

FORCE_INLINE void flush(void *p){
	asm volatile("clflush 0(%0)\n" : : "c" (p) : "rax");
}

FORCE_INLINE void mfence(void){
	asm volatile("mfence");
}

FORCE_INLINE int maccess(void *p){
	asm volatile("movq (%0), %%rax\n" : : "c" (p) : "rax");
}

/* While not used for FLUSH+RELOAD anymore, keep around for easy use. */
FORCE_INLINE uint64_t rdtsc_func(void){
	uint64_t a, d;
	asm volatile("rdtscp" : "=a"(a), "=d"(d) :: "rcx");
	return a;
}

FORCE_INLINE int64_t make_int64(uint32_t hi, uint32_t lo){
	return ((((int64_t) hi) << 32) | (int64_t) lo);
}

#define MEASURE_BEFORE(hi, lo) \
	asm volatile("cpuid\n\t" \
				 "rdtsc\n\t" \
				 "mov %%edx, %0\n\t" \
				 "mov %%eax, %1\n\t" \
				 : "=r" (hi), "=r" (lo) \
				 :: "%rax", "%rbx", "%rcx", "%rdx");

#define MEASURE_AFTER(hi, lo) \
	asm volatile("rdtscp\n\t" \
				 "mov %%edx, %0\n\t" \
				 "mov %%eax, %1\n\t" \
				 "cpuid\n\t" \
				 : "=r" (hi), "=r" (lo) \
				 :: "%rax", "%rbx", "%rcx", "%rdx");

/*
 * Flush and reload cache side-channel exploit, using the timing functions
 * adapted from ubench. Previously used more straightforward/easy rdtsc, but
 * this is more precise: less noise, overall more constant, but more cycles
 * often times.
 */
FORCE_INLINE int64_t flush_reload_func(void *ptr) {
	uint32_t lo_before, lo_after, hi_before, hi_after;

	MEASURE_BEFORE(hi_before, lo_before);
	do{
		maccess((void *) ptr);
	}while(0);
	MEASURE_AFTER(hi_after, lo_after);

	mfence();

	flush((void *) ptr);

	return make_int64(hi_after, lo_after) - make_int64(hi_before, lo_before);
}

/*
 * Event handler that will be triggered once a prefetch event occurs. When using
 * the correct counter configuration (sampling, with a period that suffices),
 * every second prefetch event should trigger it (limitation of perf/counters).
 */
static void spec_probe_handler(struct perf_event *evt, struct perf_sample_data
		*data, struct pt_regs *regs){
	unsigned int cpu;
	int i;
	int64_t time;

	cpu = get_cpu();
	put_cpu();

	/*
	 * The booby trap gadgets in the kernel will prefetch an entry in the
	 * covert channel buffer according to a stored ID -- corresponding to an
	 * indirect call site --, and cache an entry in this buffer. By checking
	 * whether an entry was cached, we can determine which exact indirect call
	 * was used to launch the detected probe.
	 *
	 * If we find entries in the buffer that were cached, we activate the static
	 * keys corresponding to these entries. Then, the indirect call sites will
	 * be mitigated through (hence reactive) code transformation, accordingly.
	 */
	for(i = 0; i < NUM_BUFFER_ENTRIES; i++){
		time = flush_reload_func(spg_covert_channel_base_entry_ptr + 
			(i * SPG_PAGE_SIZE));
		if(time < FLUSH_RELOAD_TIMING_THRESHOLD){
			/*
			 * The kernel warns us that trying to change the state of a static
			 * key should not or cannot be done in the context of an NMI
			 * handler. However, we choose to ignore this, as it works and does
			 * not give us any other problems than a big warning.
			 */
			switch_static_key_state(STATIC_KEY_ENABLED,
				&mitigation_static_keys[i]);

			/*
			 * Debug: increment number of key activations. Useful for checking
			 * how many times false positives occurred during evaluation only.
			 */
			mitigation_static_keys[i].num_activations++;

			// printk(KERN_INFO "%s [DEBUG]: (%ld) HANDLER enabled static key: %d.",
			// 	DEVICE_NAME, ktime_get_ns(), i);
		}
	}

	/*
	 * To keep track of the handled events on this CPU. Not really necessary
	 * in practice, but for debugging and evaluation this is useful. Remove
	 * this (including the get_cpu stuff) in case we need to up the speed.
	 */
	per_cpu(spec_probe_detected_cnt, cpu) =
		per_cpu(spec_probe_detected_cnt, cpu) + 1;
}

// -- SPECULATIVE PROBE DETECTION-AND-HANDLING INITIALISATION AND DESTRUCTION --

/* Remove the kernel performance counters to avoid inaccuracies or crashes. */
int exit_kernel_counters(void){
	int ret_val;
	unsigned int cpu;

	ret_val = 0;
	cpu = 0;

	preempt_disable();

	/*
	 * For every online CPU, release the individual kernel counter for tracking
	 * prefetch events. If this is not done, the results are very likely
	 * inaccurate, and crashes can occur.
	 */
	for_each_online_cpu(cpu){
		perf_event_release_kernel(per_cpu(spec_probe_perf_event, cpu));
	}

	preempt_enable();

	return ret_val;
}

/*
 * Populate the covert channel (prefetch) buffer we use to determine which
 * indirect call was used to launch a detected probe such we can reliably check
 * whether an entry was cached as a result of a PREFETCHT1 instruction.
 */
void init_covert_channel_buffer(void){
	int i, j;

	/*
	 * Skip the padding at the front and back of the buffer, and populate only
	 * the first 64 bytes (i.e., cache line size) of the entry pages.
	 */
	for(i = (PADDING_PAGE_NUMBER / 2); i < PREFETCH_BUFFER_SIZE - 
												(PADDING_PAGE_NUMBER / 2); i++){
		for(j = 0; j < CACHE_LINE_SZ; j++){
			spg_covert_channel_buffer[i * SPG_PAGE_SIZE + j] = 'a';
		}

		flush(&(spg_covert_channel_buffer[i * SPG_PAGE_SIZE]));
	}

	return;
}

/*
 * Execute this function explicitly on each CPU to be sure their counters work.
 * Might remove this later as it might not have any real effect. Check later.
 */
static void activate_kernel_counter(void *info){
	perf_event_enable(this_cpu_read(spec_probe_perf_event));
}

/* Initialise the speculative warning mechanism. */
int init_kernel_counters(void){
	int ret_val;
	unsigned int cpu;

	struct perf_event *evt;

	ret_val = 0;
	cpu = 0;

	evt = NULL;

	/*
	 * Check whether speculation control and use of the PMU are supported;
	 * these are most likely required for the detection of probes.
	 */ 
	if(!boot_cpu_has(X86_FEATURE_SPEC_CTRL)){
		printk(KERN_INFO "%s [ERROR]: Speculative checks not supported on this CPU: X86_FEATURE_SPEC_CTRL not available.\n",
			DEVICE_NAME);
		
		ret_val = -1;
		goto out;
	}

	/*
	 * Disable kernel preemption here, since accessing variables of other CPUs
	 * could mess up badly if the kernel is kicked out from here preemptively.
	 */
	preempt_disable();

	for_each_online_cpu(cpu){
		/* Initialise the (debug) prefetch event counter for each CPU. */
		per_cpu(spec_probe_detected_cnt, cpu) = 0;

		/* Create the actual counter for each CPU. */
		evt = perf_event_create_kernel_counter(&spec_probe_perf_event_attr, cpu, 
			NULL, &spec_probe_handler, NULL);

		if(IS_ERR(evt) || evt == NULL){
			printk(KERN_INFO "%s [ERROR]: Failed to create a required kernel counter on CPU %d (error: %ld). Exiting.\n",
				DEVICE_NAME, cpu, (evt != NULL ? PTR_ERR(evt) : MISC_ERR_VAL));

			ret_val = -1;
			goto out;
		}

		per_cpu(spec_probe_perf_event, cpu) = evt;
	}

	/* Reenable preemption, as code onward cannot mess up when preempted. */
	preempt_enable();

	/*
	 * Not sure if explicitly activating the counters on each CPU makes any
	 * difference. Still, can't hurt, and seems to work fine.
	 */
	on_each_cpu(activate_kernel_counter, NULL, 1);

out:
	return ret_val;
}

// -- KERNEL MODULE DEVICE MANAGEMENT --

/*
 * This function is called whenever a process attempts to execute an ioctl on
 * the associated device file.
 */
static long device_ioctl(struct file *file, unsigned int ioctl_num, 
		unsigned long ioctl_param){
	long ret_val;
	ret_val = 0;

	switch(ioctl_num){
		case IOCTL_SPG_KM_NOP:
			break;

		/*
		 * These cases below are mostly for evaluation and debugging. Normally,
		 * one would not use these, as the defence itself only enables the
		 * mitigation when it is actually needed.
		 */
		case IOCTL_SPG_KM_GET_COUNTER_STATUS:
			spec_probe_counter_status_print();

			printk(KERN_INFO "%s [DEBUG]: Printed status of kernel counters.",
				DEVICE_NAME);

			break;

		case IOCTL_SPG_KM_SWITCH_KEY_ENABLE_PARAM:
			if(ioctl_param < 0 || ioctl_param >= NUM_STATIC_KEYS){
				printk(KERN_INFO 
					"%s [ERROR]: Invalid static key index parameter.",
					DEVICE_NAME);
				ret_val = STATIC_KEY_NULL;
				goto out;
			}

			ret_val = switch_static_key_state(STATIC_KEY_ENABLED,
				&mitigation_static_keys[ioctl_param]);
			if(ret_val < 0){
				printk(KERN_INFO 
					"%s [ERROR]: Failed to enable static key (%ld).",
					DEVICE_NAME, ioctl_param);
			}

			printk(KERN_INFO "%s [DEBUG]: USER enabled static key: %ld.",
				DEVICE_NAME, ioctl_param);

			break;

		case IOCTL_SPG_KM_SWITCH_KEY_DISABLE_PARAM:
			if(ioctl_param < 0 || ioctl_param >= NUM_STATIC_KEYS){
				printk(KERN_INFO 
					"%s [ERROR]: Invalid static key index parameter.",
					DEVICE_NAME);
				ret_val = STATIC_KEY_NULL;
				goto out;
			}

			ret_val = switch_static_key_state(STATIC_KEY_DISABLED,
				&mitigation_static_keys[ioctl_param]);
			if(ret_val < 0){
				printk(KERN_INFO 
					"%s [ERROR]: Failed to disable static key (%ld).",
					DEVICE_NAME, ioctl_param);
			}

			printk(KERN_INFO "%s [DEBUG]: USER disabled static key: %ld.",
				DEVICE_NAME, ioctl_param);

			break;

		case IOCTL_SPG_KM_SWITCH_KEY_ENABLE_ALL:
			switch_static_key_state_all(STATIC_KEY_ENABLED);

			printk(KERN_INFO "%s [DEBUG]: Enabled all static keys.",
				DEVICE_NAME);

			break;

		case IOCTL_SPG_KM_SWITCH_KEY_DISABLE_ALL:
			switch_static_key_state_all(STATIC_KEY_DISABLED);

			printk(KERN_INFO "%s [DEBUG]: Disabled all static keys.",
				DEVICE_NAME);

			break;

		default:
			printk(KERN_INFO "%s [ERROR]: No such command (with code: %d).",
				DEVICE_NAME, ioctl_num);
			ret_val = -EINVAL;
	}

out:
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
 * the created device. Must be accessible globally.
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

	printk(KERN_INFO "%s [INFO]: Initialising SpecProbeGuard management module...",
		DEVICE_NAME);

	ret_val = init_kernel_counters();
	if(ret_val < 0){
		printk(KERN_INFO "%s [ERROR]: Failed to initialise speculative probe detection component (kernel counters). Exiting.\n",
			DEVICE_NAME);
		goto out;
	}

	init_covert_channel_buffer();

	ret_val = init_static_keys();
	if(ret_val < 0){
		printk(KERN_INFO "%s [ERROR]: Failed to initialise speculative probe mitigation component (static keys). Exiting.\n",
			DEVICE_NAME);
		goto out;
	}

	ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &file_ops);
	if(ret_val < 0){
		printk(KERN_INFO "%s [ERROR]: Failed to register character device. Exiting.\n",
			DEVICE_NAME);
		
		ret_val = -1;
		goto out;
	}

	printk(KERN_INFO "%s [SUCCESS]: SpecProbeGuard management module initialised.\n",
		DEVICE_NAME);

	printk(KERN_INFO "%s [INFO]: Major device number of this device is %d. Create a device file to access the device driver -- use: mknod %s c %d 0.\n",
		DEVICE_NAME, MAJOR_NUM, DEVICE_FILE_NAME, MAJOR_NUM);

out:
	return ret_val;
}

void cleanup_module(void){
	int ret_val;
	ret_val = 0;

	printk(KERN_INFO "%s [INFO]: Exiting SpecProbeGuard management module...\n",
		DEVICE_NAME);

	ret_val = exit_kernel_counters();
	if(ret_val < 0){
		printk(KERN_INFO "%s [ERROR]: Failed to clean up speculative probe detection component (kernel counters).\n",
			DEVICE_NAME);
	}

	ret_val = exit_static_keys();
	if(ret_val < 0){
		printk(KERN_INFO "%s [ERROR]: Failed to clean up speculative probe mitigation component (static keys).\n", 
			DEVICE_NAME);
	}

	unregister_chrdev(MAJOR_NUM, DEVICE_NAME);

	printk(KERN_INFO "%s [SUCCESS]: SpecProbeGuard management module exited.\n",
		DEVICE_NAME);
}
