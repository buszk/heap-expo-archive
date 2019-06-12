#include "llvm/Pass.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#include "llvm-include.h"

#include <vector>

using namespace llvm;


namespace {

static StructType* getCtorElemTy(Module *M) {
    std::vector<Type*> TyVector;
    TyVector.push_back(Int32Ty(M));
    TyVector.push_back(PointerType::getUnqual(FunctionType::get(VoidTy(M), false)));
    TyVector.push_back(Int8PtrTy(M));
    ArrayRef<Type*> TyS (TyVector);
    StructType *STy = 
       StructType::get(M->getContext(), TyS);
    return STy;
}

static ArrayType* getCtorTy(Module *M, int num) {
    ArrayType *ATy = 
        ArrayType::get(getCtorElemTy(M), num);
    return ATy;
}

static Constant* getCtorStruct(Module *M, Function *F) {
    
    SmallVector<Constant *, 10> SList;
    SList.push_back(ConstantInt::get(Int32Ty(M), 65535));
    SList.push_back(F);
    SList.push_back(ConstantPointerNull::get(Int8PtrTy(M)));
    return ConstantStruct::get(getCtorElemTy(M), SList);

}

static void addToGlobalCtors(Module *M, Function* F) {
	GlobalVariable *GCL = M->getGlobalVariable("llvm.global_ctors");
    if (GCL) {
        // Filter out the initializer elements to remove.
        ConstantArray *OldCA = cast<ConstantArray>(GCL->getInitializer());

        SmallVector<Constant *, 10> CAList;
        for (unsigned I = 0, E = OldCA->getNumOperands(); I < E; ++I)
            CAList.push_back(OldCA->getOperand(I));

        CAList.push_back(getCtorStruct(M, F));

        // Create the new array initializer.
        ArrayType *ATy =
            ArrayType::get(OldCA->getType()->getElementType(), CAList.size());
        Constant *CA = ConstantArray::get(ATy, CAList);

        // If we didn't change the number of elements, don't create a new GV.
        if (CA->getType() == OldCA->getType()) {
            GCL->setInitializer(CA);
            return;
        }

        // Create the new global and insert it next to the existing list.
        GlobalVariable *NGV =
            new GlobalVariable(CA->getType(), GCL->isConstant(), GCL->getLinkage(),
                          CA, "", GCL->getThreadLocalMode());

        GCL->getParent()->getGlobalList().insert(GCL->getIterator(), NGV);
        NGV->takeName(GCL);

        // Nuke the old list, replacing any uses with the new one.
        if (!GCL->use_empty()) {
            Constant *V = NGV;
            if (V->getType() != GCL->getType())
                V = ConstantExpr::getBitCast(V, GCL->getType());
            GCL->replaceAllUsesWith(V);
        }
        GCL->eraseFromParent();


    }
    else {
        SmallVector<Constant *, 10> CAList;
        CAList.push_back(getCtorStruct(M, F));
        ArrayType *ATy = getCtorTy(M, 1);
        Constant *CA = ConstantArray::get(ATy, CAList);

        GCL = new GlobalVariable(*M, ATy, false, GlobalValue::LinkageTypes::AppendingLinkage, CA, "llvm.global_ctors");
        
    }
}

struct HeapExpoGlobalTracker : public ModulePass {
    static char ID;

    Function *GlobalHookFunc;
    bool initialized;
    const DataLayout *DL;
    Module *M;

    HeapExpoGlobalTracker() : ModulePass(ID) { initialized = false; }


    virtual bool runOnModule(Module &Mod) {
        M = &Mod;
        if (!initialized)
            doInitialization(Mod);

        Function *CtorFunc = (Function*) M->getOrInsertFunction("init_global_vars", VoidTy(M));

        addToGlobalCtors(M, CtorFunc);

        BasicBlock *B = BasicBlock::Create(M->getContext(), "entry", CtorFunc);
        IRBuilder<> Builder(B);


        for (auto &global: M->globals()) {
            GlobalValue *G = &global;

            if (G->getName() == "llvm.global_ctors" ||
                G->getName() == "llvm.global_dtors" ||
                G->getName() == "llvm.global.annotations" ||
                G->getName() == "llvm.used") 
                continue;

            size_t elementSize = DL->getTypeAllocSize(G->getType()->getPointerElementType());
            std::vector<Value*> Args;
            Value *ptr = Builder.CreatePtrToInt(G, Int8PtrTy(M));
            Args.push_back(ptr);
            Value *size = ConstantInt::get(SizeTy(M), elementSize);
            Args.push_back(size);
            Builder.CreateCall(GlobalHookFunc, Args);
        }
        
        Builder.CreateRet(NULL);

        return false;
    }

    virtual bool doInitialization(Module &Mod) { 
        M = &Mod;
        DL = &(M->getDataLayout());
        if (!DL)
            errs() << "Data Layout required\n";

        GlobalHookFunc = (Function*)M->getOrInsertFunction("global_hook", VoidTy(M), Int8PtrTy(M), SizeTy(M));
        initialized = true;
        return false;
    }

};
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
                    if (isa<GlobalVariable>(SI->getPointerOperand()))
                        errs() << "Storing to global var\n" ;
                    if (isa<ConstantPointerNull>(SI->getValueOperand())) {
                        errs() << "Value is a nullptr\n";
                        Constant *deregptr_def = M->getOrInsertFunction("deregptr", VoidTy(M), Int8PtrTy(M));
                        Function *deregptr = cast<Function>(deregptr_def);
                        deregptr->setCallingConv(CallingConv::C);
                        std::vector <Value*> Args;
                        CastInst *cast_loc =
                            CastInst::CreatePointerCast(SI->getPointerOperand(), Int8PtrTy(M));
                        cast_loc->insertAfter(I);
                        cast_loc->setDebugLoc(I->getDebugLoc());
                        Args.push_back((Value*)cast_loc);
                        CallInst *deregptr_call = CallInst::Create(deregptr, Args, "");
                        deregptr_call->insertAfter(cast_loc);
                        deregptr_call->setDebugLoc(I->getDebugLoc());

                    } else {
                        errs() << "Value is a ptr\n";
                        Constant *regptr_def = M->getOrInsertFunction("regptr", VoidTy(M), Int8PtrTy(M), Int8PtrTy(M));
                        Function *regptr = cast<Function>(regptr_def);
                        regptr->setCallingConv(CallingConv::C);
                        std::vector <Value*> Args;
                        CastInst *cast_loc =
                            CastInst::CreatePointerCast(SI->getPointerOperand(), Int8PtrTy(M));
                        cast_loc->insertAfter(I);
                        cast_loc->setDebugLoc(I->getDebugLoc());
                        Args.push_back((Value*)cast_loc);
                        CastInst *cast_val =
                            CastInst::CreatePointerCast(SI->getValueOperand(), Int8PtrTy(M));
                        cast_val->insertAfter(cast_loc);
                        cast_val->setDebugLoc(I->getDebugLoc());
                        Args.push_back((Value*)cast_val);
                        CallInst *regptr_call = CallInst::Create(regptr, Args, "");
                        regptr_call->insertAfter(cast_val);
                        regptr_call->setDebugLoc(I->getDebugLoc());



                    }

                }
            }
        }
        return false;
    }
}; // end of struct HeapExpo
}  // end of anonymous namespace

char HeapExpo::ID = 0;
static RegisterPass<HeapExpo> X("HeapExpo", "HeapExpo Func Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
char HeapExpoGlobalTracker::ID = 1;
static RegisterPass<HeapExpoGlobalTracker> Y("HeapExpoGlobal", "HeapExpo Module Pass",
                                            false,
                                            false);

static void registerMyPass(const PassManagerBuilder &,
                           legacy::PassManagerBase &PM) {
    PM.add(new HeapExpo());
    PM.add(new HeapExpoGlobalTracker());
}

static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_ModuleOptimizerEarly,
            registerMyPass);

/*
static RegisterStandardPasses
    RegisterMyPass0(PassManagerBuilder::EP_EnableOnOptLevel0,
            registerMyPass);
            */
