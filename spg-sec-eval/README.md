# SpecProbeGuard: Security Evaluation
We evaluate SpecProbeGuard's effectiveness with regards to probing exploits by simulating a number of probing exploits from a kernel module. This module is contained here.

By compiling and using the kmod_tryout_user program, we can select different types of exploits to occur. In case SpecProbeGuard is active, it will pick up on these attacks once they hit one of its many booby traps in kernel code.

Further documentation is available in spg_eval.c.