CC = /home/daveq/Desktop/msc_project/tools/llvm_project/build/bin/clang

obj-m += spg_eval.o

# CFLAGS_spg_eval.o := -Wno-return-type -Wno-strict-prototypes -mspg-spec-probe-det -flegacy-pass-manager -Xclang -load -Xclang /home/daveq/Desktop/msc_project/tools/llvm-project/build/lib/LLVMSpeculativeProbeMitigation.so
CFLAGS_spg_eval.o := -Wno-return-type -Wno-strict-prototypes -flegacy-pass-manager -Xclang -load -Xclang /home/daveq/Desktop/msc_project/tools/llvm-project/build/lib/LLVMSpeculativeProbeMitigation.so

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean