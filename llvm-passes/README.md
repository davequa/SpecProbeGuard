# SpecProbeGuard: LLVM Passes
To implement SpecProbeGuard in the kernel, we use two LLVM passes.

The first, found in X86SpeculativeProbeDetection.cpp, implements booby trap gadgets in the kernel that an attacker can trigger with their speculative probes. This pass runs at the CodeGen level; small changes must be made to Clang to ensure this pass is recognised and can be run.

The second, SpeculativeProbeMitigation.cpp, introduces our instrumentation of indirect branches in the kernel to trace and mitigate these attacks. Simply putting this pass as a transformation in LLVM ensures one can run it during compilation.

Further documentation can be found in the respective pass file.