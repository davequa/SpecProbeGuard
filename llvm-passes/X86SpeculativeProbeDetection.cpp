//==---- X86SpeculativeProbeDetection.cpp -- Speculative Probe Detection ----=//
//
// --- SpecProbeGuard ---
//
// This LLVM pass implements the first element of SpecProbeGuard's
// instrumentation, a defence against speculative probing attacks (such as the
// Spectre-type BlindSide attack), more specifically concerning the detection
// of such attacks.
//
// With speculative probing attacks, attackers rely on speculatively jumping
// through the kernel space (using a relevant attack gadget) to look for
// interesting code gadgets that further advance their attack. These gadgets,
// in this case, consist of indirect calls that are vulnerable to speculation,
// and can be used to perform such speculative jumps to facilitate other parts
// of their attack, leak data, and/or more.
//
// Through this pass, the kernel is instrumented with booby trap code gadgets
// that, when triggered through being speculatively executed by a probe landing
// on them, execute a PREFETCHT1 instruction -- which does not occur naturally
// anywhere else in the kernel -- on specific data that tells us which attack
// gadget exactly was used to launch the probe that triggered the trap. These
// booby trap gadgets are inserted after RET instructions that close out
// functions, meaning that they are essentially 'dead code'. and will never be
// executed through normal control flow. This guarantees that no passive
// performance overhead from this defence will impact the kernel. 
//
// This instrumentation's counterpart is the element of the instrumentation that
// instruments the kernel code to allow attack source (probe) tracing and
// mitigation. These are realised through an IR-level LLVM pass that instruments
// potential attack gadgets (in our case, indirect call sites) with the means to
// trace the gadgets when used by an attacker (to construct a speculative
// probing primitives), and to apply reactive code transformation. This means
// that, once a probe was detected and was traced back to a specific attack
// gadget using its ID (which we track and disclose using per-CPU variables
// through the aforementioned instrumentation), we reactively apply our
// mitigation to this attack gadget to impede any further attacks. As a result,
// only when an attack occurs will any mitigation be deployed, ensuring no
// unnecessary performance overhead is incurred by the kernel.
//
//===----------------------------------------------------------------------===//

#include "X86.h"
#include "X86InstrBuilder.h"
#include "X86Subtarget.h"

#include "llvm/CodeGen/MachineBasicBlock.h"
#include "llvm/CodeGen/MachineFunction.h"
#include "llvm/CodeGen/MachineFunctionPass.h"
#include "llvm/CodeGen/MachineInstrBuilder.h"
#include "llvm/CodeGen/MachineModuleInfo.h"
#include "llvm/CodeGen/Passes.h"
#include "llvm/CodeGen/TargetPassConfig.h"

#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"

#include "llvm/Support/Debug.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/FileSystem.h"

#include "llvm/ADT/Statistic.h"

#include <vector>
#include <string>

using namespace llvm;

#define PASS_KEY "x86-spec-probe-det"
#define DEBUG_TYPE PASS_KEY

/*
 * Name of the per-CPU variable that will contain the address of the to-prefetch
 * memory (in our covert channel) that corresponds to the most recently
 * (speculatively) executed indirect call prior to a probe.
 */
#define TO_PREFETCH_ENTRY_VAR_NAME "spg_ind_call_entry_ptr"

/*
 * The name of the covert channel buffer we prefetch an entry in. Is only
 * required in the case the long gadget is applied.
 */
#define TO_PREFETCH_COVERT_CHANNEL_BUFFER_NAME "spg_covert_channel_base_entry_ptr"

#define NOP_SLED_SIZE 8

STATISTIC(NumSpecProbeDetTraps, "Number of probe detection traps inserted.");

//===----------------------------------------------------------------------===//
// Speculative Probe Mitigation -- Setup
//===----------------------------------------------------------------------===//
namespace {
	class X86SpeculativeProbeDetectionPass : public MachineFunctionPass{
		public:
			X86SpeculativeProbeDetectionPass() : MachineFunctionPass(ID){}
			
			StringRef getPassName() const override{
				return "X86 speculative probe detection (spec-probe-det) pass";
			}

			bool runOnMachineFunction(MachineFunction &MF) override;

			static char ID;
	};
}

char X86SpeculativeProbeDetectionPass::ID = 0;

//===----------------------------------------------------------------------===//
// Speculative Probe Detection -- Implementation
//===----------------------------------------------------------------------===//
bool X86SpeculativeProbeDetectionPass::runOnMachineFunction(MachineFunction 
	&MF){
	const X86Subtarget *Subtarget = &MF.getSubtarget<X86Subtarget>();
	const X86InstrInfo *TII = Subtarget->getInstrInfo();

	if(!Subtarget->useSpeculativeProbeDetection())
		return false;

	Module *M = const_cast<Module *>(MF.getMMI().getModule());

	const GlobalVariable *GChannelEntry = cast<GlobalVariable>(
		M->getOrInsertGlobal(TO_PREFETCH_ENTRY_VAR_NAME, Type::getInt8PtrTy(
			M->getContext())));
	if(GChannelEntry == NULL)
		return false;

	SmallVector<MachineInstr *, 32> RetsToInstrument;

	/*
	 * Consider all machine basic blocks in this function, check them for
	 * RET instructions we want to instrument; specifically, we only instrument
	 * those that are found at the end of machine basic blocks. If a relevant
	 * RET is found, save it for later.
	 */
	for(auto &MBB : MF){
		if(MBB.empty())
			continue;

		MachineInstr &MBBI = MBB.back();

		if(MBBI.getOpcode() == X86::RETQ){	
			RetsToInstrument.push_back(&MBBI);
		}
	}

	/*
	 * For all found relevant RET instructions, insert our booby trap gadget
	 * behind it, outside of the reach of normal control flow. In practice, this
	 * gadget is 'dead code', and can only be triggered by abnormal control flow
	 * -- in our case, attacker-induced speculative execution.
	 */
	for(MachineInstr *MI : RetsToInstrument){
		MachineBasicBlock *MBB = MI->getParent();

		/*
		 * Generates an INT3 instruction to mitigate straight-line speculation
		 * in the kernel. We employ this instruction in particular as it
		 * should, in the case of any false positives caused by erring
		 * predictors or such (which we have come across in our experiments),
		 * generally impede 'incorrect' speculation from the beginning of the
		 * gadget and thus reduce the rate of false positives that may occur.
		 */
		// BuildMI(MBB, DebugLoc(), TII->get(X86::INT3));

		/*
		 * We add a NOP sled to our booby trap gadget to increase the chances
		 * of an attacker-launched probe, which is most likely to randomly jump
		 * through kernel space, triggering our trap.
		 */
		for(int i = 0; i < NOP_SLED_SIZE; i++){
			BuildMI(MBB, DebugLoc(), TII->get(X86::NOOP));
		}

		/* 
		 * We assign each indirect call in the kernel a unique ID. Every time an
		 * indirect call is (speculatively) executed, its ID is used to
		 * calculate the address of an entry in our covert channel buffer, which
		 * is in turn stored in a per-CPU variable; this is all done through the
		 * instrumentation in this pass's IR-level pass counterpart.
		 *
		 * Now, we acquire this address to be able to disclose which call was
		 * used to launch the detected probe through prefetching its
		 * corresponding entry in our covert channel.
		//  */
		BuildMI(MBB, DebugLoc(), TII->get(X86::MOV64rm), X86::RBP).addReg(
			X86::RIP).addImm(0).addReg(0).addGlobalAddress(GChannelEntry).
			addReg(X86::GS);

		/*
		 * Using the acquired pre-calculated address, we prefetch data located
		 * at its entry in our covert channel buffer -- which corresponds to an
		 * indirect call. The inserted PREFETCHT1 instruction is detected by the
		 * kernel, after which we check the buffer to see which indirect call
		 * was used to mount the attack, and move to mitigating it through the
		 * insertion of an LFENCE instruction (impeding further attacker-induced
		 * speculation).
		 */
		addDirectMem(BuildMI(MBB, DebugLoc(), TII->get(X86::PREFETCHT1)),
			X86::RBP);
		
		NumSpecProbeDetTraps++;
	}

	return true;
}

//===----------------------------------------------------------------------===//
// Legacy (deprecated) Pass Manager -- Registration
//===----------------------------------------------------------------------===//
INITIALIZE_PASS(X86SpeculativeProbeDetectionPass, PASS_KEY,
	"X86 Speculative Probe Detection", false, false)

FunctionPass *llvm::createX86SpeculativeProbeDetectionPass(){
	return new X86SpeculativeProbeDetectionPass();
}