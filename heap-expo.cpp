#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include <vector>

using namespace llvm;

#define UAFFUNC "regptr"

namespace {
struct HeapExpo : public FunctionPass {
  static char ID;
  HeapExpo() : FunctionPass(ID) {}

  bool runOnFunction(Function &F) override {
    if (F.getName() == UAFFUNC) return false;
    errs() << "HeapExpo: ";
    errs().write_escaped(F.getName()) << '\n';

    for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
        Instruction *I = &*i;
        if (isa<StoreInst> (I)) {
            errs() << "Store instruction: " << *I << "\n";
            StoreInst *SI = dyn_cast<StoreInst> (I);
            if (SI->getValueOperand()->getType()->isPointerTy()) {
                errs() << "Value is a ptr\n";
                Module *M = F.getParent();
                Constant *regptr_def = M->getOrInsertFunction(UAFFUNC, Type::getVoidTy(M->getContext()), Type::getInt8PtrTy(M->getContext()), Type::getInt8PtrTy(M->getContext()));
                Function *regptr = cast<Function>(regptr_def);
                regptr->setCallingConv(CallingConv::C);
                std::vector <Value*> Args;
                CastInst *cast_loc =
                    CastInst::CreatePointerCast(SI->getPointerOperand(), Type::getInt8PtrTy(M->getContext()));
                cast_loc->insertAfter(I);
                Args.push_back((Value*)cast_loc);
                CastInst *cast_val =
                    CastInst::CreatePointerCast(SI->getValueOperand(), Type::getInt8PtrTy(M->getContext()));
                cast_val->insertAfter(cast_loc);
                Args.push_back((Value*)cast_val);
                CallInst *regptr_call = CallInst::Create(regptr, Args, "");
                regptr_call->insertAfter(cast_val);

            }
        }
    }
    return false;
  }
}; // end of struct HeapExpo
}  // end of anonymous namespace

char HeapExpo::ID = 0;
static RegisterPass<HeapExpo> X("hello", "HeapExpo World Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);

static void registerMyPass(const PassManagerBuilder &,
                           legacy::PassManagerBase &PM) {
    PM.add(new HeapExpo());
}

static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_ModuleOptimizerEarly,
            registerMyPass);

/*
static RegisterStandardPasses
    RegisterMyPass0(PassManagerBuilder::EP_EnableOnOptLevel0,
            registerMyPass);
            */
