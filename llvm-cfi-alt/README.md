# LLVM-CFI Alternative Defence
By altering the manner in which LLVM-CFI implements their simple indirect call CFI checks, we can also disrupt speculative probing attacks. Here, we made a few changes to the CGExpr.cpp file to implement a limited proof-of-concept of such a defence.

By using fsanitize=cfi-icall, in conjunction with the LLVM pass to remove any instrumented indirect calls, this defence is implemented. However, note that we only account for indirect calls that do not take any arguments or return anything; hence, a limited proof-of-concept.

Information on how exactly this defence works can be found in our paper.