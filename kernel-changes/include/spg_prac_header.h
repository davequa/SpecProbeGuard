#include <linux/jump_label.h>
#include <linux/percpu.h>

/*
 * To externally define an array of static keys, in order to ensure we can
 * access them across the entire kernel.
 *
 * As no macro exists in the kernel to declare an array of keys, we added it
 * to the jump_label.h file in the kernel.
 */
DECLARE_STATIC_KEY_ARRAY_FALSE(spg_static_keys, REQ_STATIC_KEY_NUM);

/*
 * Per-CPU variable used to store the address of an entry in our covert
 * channel that corresponds to the last indirect call that executed prior to a
 * detected speculative probe. This address is calculated using the ID of the
 * most recently executed indirect call and the base entry pointer, and will
 * be (speculatively) prefetched by an attacker triggering a booby trap.
 */
DECLARE_PER_CPU(char *, spg_ind_call_entry_ptr);
