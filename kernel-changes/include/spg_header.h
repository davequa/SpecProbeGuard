#pragma once

#include <linux/jump_label.h>
#include <linux/percpu.h>

/*
 * File containing all the declarations for the hardcoded static key branch
 * wrapper functions.
 */
#include "/path/to/include/spg_static_branch_wrappers.h"

/*
 * The total number of indirect calls in the Linux kernel that need to be
 * instrumented with their own unique static key. We round this number up to
 * to allow for more to be added (e.g., through kernel modules and such).
 */
#define IND_CALL_NUM 12643
#define NUM_BUFFER_ENTRIES (IND_CALL_NUM + 8)
#define REQ_STATIC_KEY_NUM NUM_BUFFER_ENTRIES

#define SPG_PAGE_SIZE 4096
#define CACHE_LINE_SZ 64
#define PADDING_PAGE_NUMBER 2

#define PREFETCH_BUFFER_SIZE (NUM_BUFFER_ENTRIES + PADDING_PAGE_NUMBER)

/*
 * To externally define an array of static keys, in order to ensure we can
 * access them across the entire kernel.
 *
 * As no macro exists in the kernel to declare an array of keys, we added it
 * to the jump_label.h file in the kernel.
 */
DECLARE_STATIC_KEY_ARRAY_FALSE(spg_static_keys, REQ_STATIC_KEY_NUM);

/*
 * Array of chars that makes up the covert channel buffer. In size, it aligns
 * with the total number of indirect calls in the kernel (with padding). Lets
 * us execute a FLUSH+RELOAD attack to determine which indirect call entry
 * was prefetched, and thus which indirect call was used to attack.
 */
extern char spg_covert_channel_buffer[PREFETCH_BUFFER_SIZE * SPG_PAGE_SIZE] 
	__attribute__ ((aligned (64)));

/*
 * Pointer to the base of the entries that correspond to indirect call IDs in
 * the covert channel buffer. Will be used in the booby trap gadgets to
 * prefetch data from this buffer according to the indirect call used to probe,
 * enabling accurate detection.
 */
extern char *spg_covert_channel_base_entry_ptr;

/*
 * Per-CPU variable used to store the address of an entry in our covert
 * channel that corresponds to the last indirect call that executed prior to a
 * detected speculative probe. This address is calculated using the ID of the
 * most recently executed indirect call and the base entry pointer, and will
 * be (speculatively) prefetched by an attacker triggering a booby trap.
 */
DECLARE_PER_CPU(char *, spg_ind_call_entry_ptr);
// DECLARE_PER_CPU(uint64_t, spg_ind_call_entry_ptr);