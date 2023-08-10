//==---- SpeculativeProbeMitigation.cpp -- Speculative Probe Mitigation ----==//
//
// --- SpecProbeGuard ---
//
// This LLVM pass implements the second element of SpecProbeGuard's
// instrumentation, a defence against speculative probing attacks (such as the
// Spectre-type BlindSide attack), specifically concerning the actual mitigation
// of such attacks. This part of the instrumentation's counterpart, speculative
// probe detection, enables the detection of such probes through the
// instrumentation of target code with booby trap gadgets. Whenever a probe was
// detected in this manner, this pass's instrumentation is utilised to perform
// reactive code transformation, offering low-overhead defensive measures that
// effectively impede further probing attacks.
//
// More specifically, this reactive code transformation is concerned with the
// instrumentation of indirect calls (the source of the relevant speculative
// probing attacks; useful attack gadgets) with static key branches. These
// branches can be switched by enabling or disabling their associated static
// key(s), and code from either branch will be patched in on-the-fly by the
// kernel. For our mitigation and this pass, there are two branches: the first
// concerns our method used to stop attacker-induced speculation -- an LFENCE
// instruction, while the second is an extension of speculative probe detection,
// and attack source (probe) tracing, which, by tracking the ID of the indirect
// call that was executed (speculatively) most recently and calculating the
// address of an entry in our covert channel buffer, and applying our covert
// channel to determine which attack gadget was used, allows for accurate attack
// detection and source tracing.
//
// By applying reactive code transformation, which here in essence concerns
// inserting a costly mitigation only when an attack was detected and only for
// the code the attacker used to construct their speculative probing primitive,
// where this attack was mounted from, we avoid incurring any unnecessary
// overhead penalties in the kernel. As such, this defence offers an effective
// low-overhead method for mitigating speculative probing attacks.
//
//===----------------------------------------------------------------------===//

#include "llvm/Pass.h"
#include "llvm/InitializePasses.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/PassRegistry.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"

#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"

#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "llvm/Support/Debug.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"

#include "llvm/ADT/Statistic.h"

#include <stdio.h>
#include <stdlib.h>
#include <iostream>

using namespace llvm;

#define DEBUG_TYPE "spec-probe-mit"

/* To work with static keys and our array of pre-defined keys in the kernel. */
#define STATIC_KEY_ARRAY_NAME "spg_static_keys"

/*
 * Name of the wrapper function of static branch functionalities we inline in
 * the kernel to allow for the relevant kernel macros to be used. Such macros
 * are not accessible through LLVM, otherwise.
 */
#define STATIC_BRANCH_WRAPPER_FUNC_NAME_PREFIX "spg_static_branch_wrapper_"

/* Name of the file we use to track indirect call IDs in the kernel. */
#define IND_ID_TRACK_FILE_NAME "/home/daveq/Desktop/kernels/spec_probe_mit_ind_cnt.txt"

STATISTIC(NumAttGadgetInstrumented, "Number of attack gadgets instrumented.");

//===----------------------------------------------------------------------===//
// Speculative Probe Mitigation -- Setup
//===----------------------------------------------------------------------===//
/* To support the new pass manager running this pass. */
class SpeculativeProbeMitigationPass : public 
	PassInfoMixin<SpeculativeProbeMitigationPass> {
	public:
		PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
		bool runOnFunction(Function &F);
};

/* To support the legacy (deprecated) pass manager running this pass. */
struct SpeculativeProbeMitigationLegacyPass : public FunctionPass {
	static char ID;

	SpeculativeProbeMitigationLegacyPass() : FunctionPass(ID) {}
	bool runOnFunction(Function &F) override;

	SpeculativeProbeMitigationPass pass;
};

//===----------------------------------------------------------------------===//
// Speculative Probe Mitigation -- Helper Functions
//===----------------------------------------------------------------------===//
int getNewIndirectCallID(void){
	int indirectCallID;
	indirectCallID = 0;

	bool fileExists;
	fileExists = false;

	/*
	 * Since we (unfortunately) cannot keep a state across LLVM-instrumented
	 * modules with a pass like this one, we use a file to track the indirect
	 * call IDs we assign to all indirect call sites in the kernel.
	 *
	 * This solution is quite bad, but it works for now. If possible, replace
	 * this with something better later (e.g., linktime optimisations,
	 * debug information, or anything other than file stuff), which also
	 * supports loading/unloading kernel modules, not wasting static keys or
	 * covert channel memory, etc.
	 *
	 * However, keep this for now.
	 */
	FILE *indirectCallIDFile = fopen(IND_ID_TRACK_FILE_NAME, "r+");
	if(indirectCallIDFile == NULL){
		indirectCallIDFile = fopen(IND_ID_TRACK_FILE_NAME, "w+");
		if(indirectCallIDFile == NULL)
			return -1;
	}else{
		fileExists = true;
	}

	if(fileExists){
		if(fscanf(indirectCallIDFile, "%d", &indirectCallID) < 0)
			return -1;
	}

	indirectCallIDFile = freopen(IND_ID_TRACK_FILE_NAME, "w+",
		indirectCallIDFile);
	if(indirectCallIDFile == NULL)
		return -1;

	indirectCallID++;

	fprintf(indirectCallIDFile, "%d", indirectCallID);
	fflush(indirectCallIDFile);

	fclose(indirectCallIDFile);

	/*
	 * Since we increment the counter to already write back the next call's ID
	 * to the file, we subtract the returned (current) ID by one.
	 */
	return indirectCallID - 1;
}

//===----------------------------------------------------------------------===//
// Speculative Probe Mitigation -- Main Implementation
//===----------------------------------------------------------------------===//
bool SpeculativeProbeMitigationPass::runOnFunction(Function &F){
	Module *M = const_cast<Module *>(F.getParent());

	SmallVector<CallInst *, 32> IndirectCallsToInstrument;
	
	/*
	 * Iterate over all basic blocks of the function to consider all indirect
	 * branches/calls. To ensure completeness, we do not skip any indirect calls
	 * that we think might not be part of relevant attack gadgets, and instead
	 * target all of them for instrumentation. If one can never be used by an
	 * attacker to construct a speculative probing primitive, we only waste
	 * a static key and a page of memory for it, which is acceptable.
	 */
	for(auto &BB : F){
		if(BB.empty())
			continue;

		/* Check all instructions for indirect calls we need to instrument. */
		for(auto BBI = BB.begin(); BBI != BB.end(); BBI++){
			CallInst *IndBI = dyn_cast<CallInst>(BBI);		
			if(!IndBI || !IndBI->isIndirectCall())
				continue;

			IndirectCallsToInstrument.push_back(IndBI);
		}
	}

	/* Instrument every indirect call found in this function. */
	for(CallInst *IndBI : IndirectCallsToInstrument){
		IRBuilder<> Builder(M->getContext());

		int indirectCallID = getNewIndirectCallID();
		if(indirectCallID < 0)
			return false;

		/*
		 * Set up a function call to wrapper functions we have defined in the
		 * kernel that contain the static key branches: one that executes an
		 * LFENCE instruction -- to impede speculation -- in the 'then' branch
		 * (disabled by default), and one that keeps track of the instrumented
		 * indirect call's ID and calculates a corresponding entry in our covert
		 * channel buffer -- to enable precise probe (source) detection -- in
		 * the 'else' branch (enabled by default). These are then switched on
		 * command using the static key that is uniquely assigned to this
		 * indirect call site.
		 *
		 * In this version, each function we insert is unique due to static keys
		 * not being assignable dynamically (as a result of their implementation
		 * in the kernel). Hence, each function has a different static key
		 * hardcoded in it to allow it to switch branches. While this is not
		 * scalable or very practical, it works.
		 */
		std::string StaticKeyFuncNameNew =
			STATIC_BRANCH_WRAPPER_FUNC_NAME_PREFIX +
			std::to_string(indirectCallID);
		FunctionCallee StaticKeyBranchCheckFunc = M->getOrInsertFunction(
			StaticKeyFuncNameNew, Type::getVoidTy(M->getContext()),
			Type::getInt64Ty(M->getContext()));

		/*
		 * The argument for this function will be an unsigned integer that
		 * corresponds in value to this indirect call's unique ID (out of all
		 * instrumented indirect calls).
		 */
		SmallVector<Value *, 8> FuncArgs;

		FuncArgs.push_back(ConstantInt::get(Type::getInt64Ty(M->getContext()),
			indirectCallID, false));

		/* Create and insert said call, and from there inline it. */
		CallInst *StaticKeyBranchCheckCall = Builder.CreateCall(
			StaticKeyBranchCheckFunc.getFunctionType(),
			StaticKeyBranchCheckFunc.getCallee(), makeArrayRef(FuncArgs));
		StaticKeyBranchCheckCall->insertBefore(IndBI);

		InlineFunctionInfo ifi;
		InlineFunction(*StaticKeyBranchCheckCall, ifi);

		NumAttGadgetInstrumented++;
	}

	return true;
}

/* To support the new pass manager running this pass. */
PreservedAnalyses SpeculativeProbeMitigationPass::run(Function &F,
		FunctionAnalysisManager &AM){
	return (runOnFunction(F) ? llvm::PreservedAnalyses::none() : 
		llvm::PreservedAnalyses::all());
}

/* To support the legacy (deprecated) pass manager running this pass. */
bool SpeculativeProbeMitigationLegacyPass::runOnFunction(Function &F){
	return pass.runOnFunction(F);
}

//===----------------------------------------------------------------------===//
// New Pass Manager -- Registration
//===----------------------------------------------------------------------===//
llvm::PassPluginLibraryInfo getSpeculativeProbeMitigationPassPluginInfo() {
	return {LLVM_PLUGIN_API_VERSION, "SpeculativeProbeMitigation",
		LLVM_VERSION_STRING, [](PassBuilder &PB) {
			PB.registerPipelineParsingCallback(
				[](StringRef Name, FunctionPassManager &FPM,
				   ArrayRef<PassBuilder::PipelineElement>) {
				  if (Name == "spec-probe-mit") {
					FPM.addPass(SpeculativeProbeMitigationPass());
					return true;
				  }
				  return false;
				});
		  }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo 
llvmGetPassPluginInfo() {
  return getSpeculativeProbeMitigationPassPluginInfo();
}

//===----------------------------------------------------------------------===//
// Legacy (deprecated) Pass Manager -- Registration
//===----------------------------------------------------------------------===//
char SpeculativeProbeMitigationLegacyPass::ID = 0;
static RegisterPass<SpeculativeProbeMitigationLegacyPass>X(
	"legacy-spec-probe-mit", "Legacy speculative probe mitigation", false,
	false);

/*
 * This below is (unfortunately) necessary to get this stuff to work with
 * LLVM/clang at all.
 * 
 * To actually use it, do the following:
 * clang -flegacy-pass-manager -Xclang -load -Xclang <pass.so> <target_file.c>
 *
 * Note that from LLVM 14.0.0 and up, the legacy pass manager is removed
 * entirely, such that this above method cannot be used anymore. So, stick to
 * LLVM 13.0.0 to be safe (and save yourself the terrible headache).
 */
static void registerPass(const PassManagerBuilder &, 
	legacy::PassManagerBase &PM){
	PM.add(new SpeculativeProbeMitigationLegacyPass());
}

static RegisterStandardPasses RegisterMyPass(
	PassManagerBuilder::EP_EarlyAsPossible, registerPass);