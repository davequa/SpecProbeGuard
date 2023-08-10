//==----- IndirectCallRemove.cpp --- Removes Indirect Calls from Files -----==//
//
// Removes indirect calls from basic blocks to support the insertion of an
// alternative defence against speculative probing attacks. In the gadgets we
// insert to implement our defensive measures, we move the indirect call to a
// register through a CMOV, only calling it when we have established through
// CFI that the indirect call's target was valid.
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

#define DEBUG_TYPE "indirect-call-remove"

//===----------------------------------------------------------------------===//
// Indirect Call Removal -- Setup
//===----------------------------------------------------------------------===//
/* To support the new pass manager running this pass. */
class IndirectCallRemovePass : public 
	PassInfoMixin<IndirectCallRemovePass> {
	public:
		PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM);
		bool runOnFunction(Function &F);
};

/* To support the legacy (deprecated) pass manager running this pass. */
struct IndirectCallRemoveLegacyPass : public FunctionPass {
	static char ID;

	IndirectCallRemoveLegacyPass() : FunctionPass(ID) {}
	bool runOnFunction(Function &F) override;

	IndirectCallRemovePass pass;
};

//===----------------------------------------------------------------------===//
// Indirect Call Removal -- Main Implementation
//===----------------------------------------------------------------------===//
bool IndirectCallRemovePass::runOnFunction(Function &F){
	SmallVector<CallInst *, 32> IndirectCallsToInstrument;

	/*
	 * Check whether the function we are instrumenting may actually have its
	 * indirect calls removed. Namely, we insert a few ourselves as well, and
	 * these may never be touched by this pass.
	 */
	// TO-DO!
	// string match "cfi_slow_path_func_wrapper" prefix, then skip
	
	/*
	 * Iterate over all basic blocks of the function to consider all indirect
	 * branches/calls. To ensure completeness, we do not skip any indirect calls
	 * that we think might not be part of relevant attack gadgets, and instead
	 * target all of them for instrumentation.
	 */
	for(auto &BB : F){
		if(BB.empty())
			continue;

		/* Check all instructions for indirect calls we need to remove. */
		for(auto BBI = BB.begin(); BBI != BB.end(); BBI++){
			CallInst *IndBI = dyn_cast<CallInst>(BBI);		
			if(!IndBI || !IndBI->isIndirectCall())
				continue;

			IndirectCallsToInstrument.push_back(IndBI);
		}
	}

	/* For every indirect call found, remove it from its parent basic block. */
	for(CallInst *IndBI : IndirectCallsToInstrument){
		IndBI->removeFromParent();
	}

	return true;
}

/* To support the new pass manager running this pass. */
PreservedAnalyses IndirectCallRemovePass::run(Function &F,
		FunctionAnalysisManager &AM){
	return (runOnFunction(F) ? llvm::PreservedAnalyses::none() : 
		llvm::PreservedAnalyses::all());
}

/* To support the legacy (deprecated) pass manager running this pass. */
bool IndirectCallRemoveLegacyPass::runOnFunction(Function &F){
	return pass.runOnFunction(F);
}

//===----------------------------------------------------------------------===//
// New Pass Manager -- Registration
//===----------------------------------------------------------------------===//
llvm::PassPluginLibraryInfo getIndirectCallRemovePassPluginInfo() {
	return {LLVM_PLUGIN_API_VERSION, "IndirectCallRemove",
		LLVM_VERSION_STRING, [](PassBuilder &PB) {
			PB.registerPipelineParsingCallback(
				[](StringRef Name, FunctionPassManager &FPM,
				   ArrayRef<PassBuilder::PipelineElement>) {
				  if (Name == "indirect-call-remove") {
					FPM.addPass(IndirectCallRemovePass());
					return true;
				  }
				  return false;
				});
		  }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo 
llvmGetPassPluginInfo() {
  return getIndirectCallRemovePassPluginInfo();
}

//===----------------------------------------------------------------------===//
// Legacy (deprecated) Pass Manager -- Registration
//===----------------------------------------------------------------------===//
char IndirectCallRemoveLegacyPass::ID = 0;
static RegisterPass<IndirectCallRemoveLegacyPass>X(
	"legacy-indirect-call-remove", "Legacy Indirect Call Removal", false,
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
	PM.add(new IndirectCallRemoveLegacyPass());
}

static RegisterStandardPasses RegisterMyPass(
	PassManagerBuilder::EP_EarlyAsPossible, registerPass);