#include "/home/daveq/Desktop/Projects/SpecProbeGuard/kernels/linux-6.6/include/spg_static_branch_wrappers.h"
#include "/home/daveq/Desktop/Projects/SpecProbeGuard/kernels/linux-6.6/include/spg_prac_header.h"

/*
 * The total set of static keys we use to apply reactive code transformation in
 * the kernel source, each uniquely associated with a specific indirect call.
 */
DEFINE_STATIC_KEY_ARRAY_FALSE(spg_static_keys, REQ_STATIC_KEY_NUM);

/*
 * Array of chars that makes up the covert channel buffer. In size, it aligns
 * with the total number of indirect calls in the kernel (with padding). Lets
 * us execute a FLUSH+RELOAD attack to determine which indirect call entry
 * was prefetched, and thus which indirect call was used to attack.
 *
 * This buffer will be initialised in the defence manager kernel module, which
 * is preferably loaded in shortly after kernel startup.
 */
char spg_covert_channel_buffer[PREFETCH_BUFFER_SIZE * SPG_PAGE_SIZE] 
	__attribute__ ((aligned (64)));

/*
 * Pointer to the base of the entries that correspond to indirect call IDs in
 * the covert channel buffer. Will be used in the booby trap gadgets to
 * prefetch data from this buffer according to the indirect call used to probe,
 * enabling accurate detection.
 */
char *spg_covert_channel_base_entry_ptr = 
	&(spg_covert_channel_buffer[SPG_PAGE_SIZE]);

/*
 * Per-CPU variable used to store the address of an entry in our covert
 * channel that corresponds to the last indirect call that executed prior to a
 * detected speculative probe. This address is calculated using the ID of the
 * most recently executed indirect call and the base entry pointer, and will
 * be (speculatively) prefetched by an attacker triggering a booby trap.
 */
DEFINE_PER_CPU(char *, spg_ind_call_entry_ptr);

/*
 * Export all symbols relevant to the speculative probe defence to be
 * available to kernel modules (for debugging purposes and mitigation
 * component/defence management).
 */
EXPORT_SYMBOL(spg_static_keys);
EXPORT_SYMBOL(spg_covert_channel_buffer);
EXPORT_SYMBOL(spg_covert_channel_base_entry_ptr);
EXPORT_SYMBOL(spg_ind_call_entry_ptr);
