CC = /home/daveq/Desktop/msc_project/tools/llvm_project/build/bin/clang

obj-m += spg_manager.o

CFLAGS_spg_manager.o := -Wno-return-type -Wno-strict-prototypes #-mspec-probe-det -flegacy-pass-manager -Xclang -load -Xclang /home/daveq/Desktop/msc_project/tools/llvm-project/build/lib/LLVMSpeculativeProbeMitigation.so

all:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
		make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean