#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "llvm-include.h"

#include <vector>

using namespace llvm;


namespace {
struct HeapExpo : public FunctionPass {
    static char ID;
    HeapExpo() : FunctionPass(ID) {}

    bool runOnFunction(Function &F) override {
//        if (F.getName() == "regptr") return false;
//        if (F.getName() == "deregptr") return false;
        Module *M = F.getParent();
        errs() << "HeapExpo: ";
        errs().write_escaped(F.getName()) << '\n';

        for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
            Instruction *I = &*i;
            if (isa<StoreInst> (I)) {
                errs() << "Store instruction: " << *I << "\n";
                StoreInst *SI = dyn_cast<StoreInst> (I);
                if (SI->getValueOperand()->getType()->isPointerTy()) {
                    if (isa<ConstantPointerNull>(SI->getValueOperand())) {
                        errs() << "Value is a nullptr\n";
                        Constant *deregptr_def = M->getOrInsertFunction("deregptr", VoidTy(M), Int8PtrTy(M));
                        Function *deregptr = cast<Function>(deregptr_def);
                        deregptr->setCallingConv(CallingConv::C);
                        std::vector <Value*> Args;
                        CastInst *cast_loc =
                            CastInst::CreatePointerCast(SI->getPointerOperand(), Int8PtrTy(M));
                        cast_loc->insertAfter(I);
                        Args.push_back((Value*)cast_loc);
                        CallInst *deregptr_call = CallInst::Create(deregptr, Args, "");
                        deregptr_call->insertAfter(cast_loc);

                    } else {
                        errs() << "Value is a ptr\n";
                        Constant *regptr_def = M->getOrInsertFunction("regptr", VoidTy(M), Int8PtrTy(M), Int8PtrTy(M));
                        Function *regptr = cast<Function>(regptr_def);
                        regptr->setCallingConv(CallingConv::C);
                        std::vector <Value*> Args;
                        CastInst *cast_loc =
                            CastInst::CreatePointerCast(SI->getPointerOperand(), Int8PtrTy(M));
                        cast_loc->insertAfter(I);
                        Args.push_back((Value*)cast_loc);
                        CastInst *cast_val =
                            CastInst::CreatePointerCast(SI->getValueOperand(), Int8PtrTy(M));
                        cast_val->insertAfter(cast_loc);
                        Args.push_back((Value*)cast_val);
                        CallInst *regptr_call = CallInst::Create(regptr, Args, "");
                        regptr_call->insertAfter(cast_val);

                    }

                }
            }
            /*
            else if (isa<CallInst> (I)) {
                CallInst *CI = dyn_cast<CallInst>(I);
                Function *F = CI->getCalledFunction();
                if (F) {
                    StringRef funcname = F->getName();
                    if (funcname == "malloc") {
                        errs()<< "Calls to malloc detected\n";
                        Constant *alloc_hook_def = M->getOrInsertFunction("alloc_hook", VoidTy(M), Int8PtrTy(M), SizeTy(M));
                        Function *alloc_hook = cast<Function>(alloc_hook_def);
                        alloc_hook->setCallingConv(CallingConv::C);
                        std::vector <Value*> Args;
                        CastInst *cast_addr =
                            CastInst::CreatePointerCast(CI, Int8PtrTy(M));
                        cast_addr->insertAfter(CI);
                        Args.push_back((Value*)cast_addr);
                        Args.push_back((Value*)CI->getOperand(0));
                        CallInst *alloc_hook_call = CallInst::Create(alloc_hook, Args, "");
                        alloc_hook_call->insertAfter(cast_addr);



                    } else if (funcname == "realloc") {
                        errs()<< "Calls to realloc detected\n";
                        Constant *realloc_hook_def = M->getOrInsertFunction("realloc_hook", VoidTy(M), Int8PtrTy(M), Int8PtrTy(M), SizeTy(M));
                        Function *realloc_hook = cast<Function>(realloc_hook_def);
                        realloc_hook->setCallingConv(CallingConv::C);
                        std::vector <Value*> Args;
                        Args.push_back((Value*)CI->getOperand(0));
                        CastInst *cast_new_addr = 
                            CastInst::CreatePointerCast(CI, Int8PtrTy(M));
                        cast_new_addr->insertAfter(CI);
                        Args.push_back((Value*)cast_new_addr);
                        Args.push_back((Value*)CI->getOperand(1));
                        CallInst *realloc_hook_call = CallInst::Create(realloc_hook, Args, "");
                        realloc_hook_call->insertAfter(cast_new_addr);

                    } else if (funcname == "free") {
                        errs()<< "Calls to free detected\n";
                        Constant *dealloc_hook_def = M->getOrInsertFunction("dealloc_hook", VoidTy(M), Int8PtrTy(M));
                        Function *dealloc_hook = cast<Function>(dealloc_hook_def);
                        dealloc_hook->setCallingConv(CallingConv::C);
                        std::vector <Value*> Args;
                        Args.push_back((Value*)CI->getOperand(0));
                        CallInst *dealloc_hook_call = CallInst::Create(dealloc_hook, Args, "");
                        dealloc_hook_call->insertAfter(CI);

                    }

                }
            } */
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
