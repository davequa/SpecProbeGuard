# SpecProbeGuard
SpecProbeGuard: a reactive defense against speculative probing attacks in the Linux kernel.

SpecProbeGuard balances security and performance by deploying expensive mitigations against speculative probing attacks only when necessary. It detects an attacker's probes via booby traps it embeds in the kernel, and traces them to identify the attacker's speculative probing primitive. Thereafter, it applies reactive code transformation to mitigate only this offending code. This, more specifically, means we dismantle an attacker's speculative probing primitive alone by patching its code -- on the fly -- to render further exploitation impossible, doing so at a minimal cost for the entire system.
