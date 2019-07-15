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

#include <exception>
#include <cxxabi.h>
#include <sstream>
#include <time.h>
#include <cstdlib>

#include <vector>

#define LVL_ERROR   1
#define LVL_WARNING 2
#define LVL_INFO    3
#define LVL_DEBUG   4
#define DEBUG_LVL LVL_INFO
#define LOG(LVL) ((DEBUG_LVL >= LVL) ? llvm::errs() : llvm::nulls())


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
    SList.push_back(ConstantInt::get(Int32Ty(M), 2));
    SList.push_back(F);
    SList.push_back(ConstantPointerNull::get(Int8PtrTy(M)));
    return ConstantStruct::get(getCtorElemTy(M), SList);

}

static std::string demangleName(std::string input) {
    int status;
    char *real_name;

    real_name = abi::__cxa_demangle(input.c_str(), 0, 0, &status);
    if (real_name) {
        std::string res(real_name);
        free(real_name);
        return "c++:" + res ;
    } else {
        return input;
    }
}

static void addToGlobalCtors(Module *M, Function* F) {
	GlobalVariable *GCL = M->getGlobalVariable("llvm.global_ctors");
    if (GCL) {
        // Filter out the initializer elements to remove.
        if (isa<ConstantArray>(GCL->getInitializer())) {
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
            return;
        }
        assert(GCL->use_empty());
        GCL->eraseFromParent();
    }
    
    SmallVector<Constant *, 10> CAList;
    CAList.push_back(getCtorStruct(M, F));
    ArrayType *ATy = getCtorTy(M, 1);
    Constant *CA = ConstantArray::get(ATy, CAList);

    GCL = new GlobalVariable(*M, ATy, false, GlobalValue::LinkageTypes::AppendingLinkage, CA, "llvm.global_ctors");
        
}

static bool isStackPtr(Value *V) {
    if (!isa<User>(V))
        return false;

    User *U = (User*)V;

    if (isa<AllocaInst>(U)) {
        return true;
    }
    else if (isa<BinaryOperator>(U)) {
        return isStackPtr(U->getOperand(0)) || isStackPtr(U->getOperand(1));
    }
    return false;
}
/*
static bool isConstantGlobalPtr(Value *V) {
    if (!isa<User>(V))
        return false;

    User *U = (User*)V;

    if (isa<GlobalVariable>(U)) {
        return true;
    }
    else if (isa<BinaryOperator>(U)) {
        return isConstantGlobalPtr(U->getOperand(0)) || isConstantGlobalPtr(U->getOperand(1));
    }
    return false;
}
*/
struct HeapExpoGlobalTracker : public ModulePass {
    static char ID;

    Function *GlobalHookFunc;
    const DataLayout *DL;
    Module *M;
    
    bool initialized;

    HeapExpoGlobalTracker() : ModulePass(ID) { initialized = false; }

    virtual bool runOnModule(Module &Mod) {
        size_t global_instr_cnt = 0;
        
        Module *M = &Mod;
        DL = &(M->getDataLayout());
        if (!DL)
            LOG(LVL_ERROR) << "Data Layout required\n";

        GlobalHookFunc = (Function*)M->getOrInsertFunction("global_hook", VoidTy(M), Int8PtrTy(M), SizeTy(M));
        
        doInitialization(Mod);

        std::string CtorFuncName = "init_global_vars_" + M->getModuleIdentifier();

        Function *CtorFunc = (Function*) M->getOrInsertFunction(CtorFuncName, VoidTy(M));

        addToGlobalCtors(M, CtorFunc);

        BasicBlock *B = BasicBlock::Create(M->getContext(), "entry", CtorFunc);
        IRBuilder<> Builder(B);


        for (auto &global: M->globals()) {
            GlobalValue *G = &global;
            if (!isa<GlobalVariable>(G)) 
                continue;
            GlobalVariable *GV = (GlobalVariable*) G;

            if (G->getName() == "llvm.global_ctors" ||
                G->getName() == "llvm.global_dtors" ||
                G->getName() == "llvm.global.annotations" ||
                G->getName() == "llvm.used") 
                continue;
    
            /* Ignore constant global variables */
            if (GV->isConstant())
                continue;

            size_t elementSize = DL->getTypeAllocSize(G->getType()->getPointerElementType());
            std::vector<Value*> Args;
            Value *ptr = Builder.CreatePointerCast(G, Int8PtrTy(M));
            Args.push_back(ptr);
            Value *size = ConstantInt::get(SizeTy(M), elementSize);
            Args.push_back(size);
            Builder.CreateCall(GlobalHookFunc, Args);
            global_instr_cnt ++;
        }
        
        Builder.CreateRet(NULL);
        
        std::ostringstream ss;
        ss << "Instrumented tracking to " << global_instr_cnt << 
            " global variables\n";
        LOG(LVL_INFO) << ss.str();
        return false;
    }

};

struct HeapExpoFuncTracker : public FunctionPass  {
    static char ID;
    bool initialized;
    Module *M;
    Function *regptr, *deregptr;
    Function *func;
    size_t store_instr_cnt = 0;
    size_t stack_store_instr_cnt = 0;
    size_t store_const_global_cnt = 0;

    HeapExpoFuncTracker() : FunctionPass(ID) {
        initialized = false;
    }
    
    void instrDereg(StoreInst *SI) {

        DebugLoc DLoc = SI->getDebugLoc();
        if (!DLoc)
            DLoc = DebugLoc::get(0, 0, (MDNode*)func->getSubprogram());
        
        uint32_t cur_call = rand() & 0xffffffff;
        ConstantInt *CurCall = ConstantInt::get(Int32Ty(M), cur_call);

        std::vector <Value*> Args;
        CastInst *cast_loc =
            CastInst::CreatePointerCast(SI->getPointerOperand(), Int8PtrTy(M));
        cast_loc->insertBefore(SI);
        cast_loc->setDebugLoc(DLoc);
        Args.push_back((Value*)cast_loc);
        Args.push_back((Value*)CurCall);

        LOG(LVL_DEBUG) << "CurCall Type: " << *CurCall->getType() << '\n';
        LOG(LVL_DEBUG) << "Cast Loc Type: " << *cast_loc->getType() << '\n';
        LOG(LVL_DEBUG) << "Func Type: " << *deregptr << '\n';
        
        CallInst *deregptr_call = CallInst::Create(deregptr, Args, "");
        deregptr_call->insertBefore(SI);
        deregptr_call->setDebugLoc(DLoc);
    }

    void instrReg(StoreInst *SI) {

        DebugLoc DLoc = SI->getDebugLoc();
        if (!DLoc)
            DLoc = DebugLoc::get(0, 0, (MDNode*)func->getSubprogram());
       
        std::vector <Value*> Args;

        uint32_t cur_call = rand() & 0xffffffff;
        ConstantInt *CurCall = ConstantInt::get(Int32Ty(M), cur_call);

        CastInst *cast_loc =
            CastInst::CreatePointerCast(SI->getPointerOperand(), Int8PtrTy(M));
        cast_loc->insertBefore(SI);
        cast_loc->setDebugLoc(DLoc);
        Args.push_back((Value*)cast_loc);
        CastInst *cast_val =
            CastInst::CreatePointerCast(SI->getValueOperand(), Int8PtrTy(M));
        cast_val->insertBefore(SI);
        cast_val->setDebugLoc(DLoc);
        Args.push_back((Value*)cast_val);
        Args.push_back((Value*)CurCall);
        CallInst *regptr_call = CallInst::Create(regptr, Args, "");
        regptr_call->insertBefore(SI);
        regptr_call->setDebugLoc(DLoc);
    }

    virtual bool runOnFunction(Function &F) {

        LOG(LVL_DEBUG) << "HeapExpo: ";
        LOG(LVL_DEBUG).write_escaped(demangleName(F.getName())) << '\n';
        
        if (M != F.getParent()) {
            M = F.getParent();
            initialized = false;
        }

        if (!initialized) 
            initialize(M);

        func = &F;
        for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
            Instruction *I = &*i;
            if (isa<StoreInst> (I)) {
                LOG(LVL_DEBUG) << "Store instruction: " << *I << "\n";
                StoreInst *SI = dyn_cast<StoreInst> (I);
                if (SI->getValueOperand()->getType()->isPointerTy()) {
                    if (isa<GlobalVariable>(SI->getPointerOperand()))
                        LOG(LVL_DEBUG) << "Storing to global var\n" ;
                    if (isa<ConstantPointerNull>(SI->getValueOperand())) {
                        LOG(LVL_DEBUG) << "Value is a nullptr\n";
                            
                        instrDereg(SI);
                        
                        store_instr_cnt ++;

                    } else {
                        LOG(LVL_DEBUG) << "Value is a ptr\n";
                        
                        /* Don't instr if storing to stack */
                        if (isStackPtr(SI->getPointerOperand())) {
                            stack_store_instr_cnt++;
                            continue;
                        }

                        //if (isConstantGlobalPtr(SI->getValueOperand())) 
                        if (isa<Constant>(SI->getValueOperand())) {
                            instrDereg(SI);
                            store_const_global_cnt++;
                            continue;
                        }

                        instrReg(SI);

                        store_instr_cnt ++;

                    }

                }
            }
        }
        return false;

    }
    
    bool initialize(Module *M) { 

        Constant *deregptr_def = M->getOrInsertFunction("deregptr", VoidTy(M), Int8PtrTy(M), Int32Ty(M));
        deregptr = cast<Function>(deregptr_def);
        deregptr->setCallingConv(CallingConv::C);
        
        Constant *regptr_def = M->getOrInsertFunction("regptr", VoidTy(M), Int8PtrTy(M), Int8PtrTy(M), Int32Ty(M));
        regptr = cast<Function>(regptr_def);
        regptr->setCallingConv(CallingConv::C);

        srand(time(NULL));
        
        initialized = true;
        return false;
    }

    virtual bool doFinalization(Module &Mod) {
        std::ostringstream ss;
        ss << "Instrumented tracking to " << store_instr_cnt << 
            " all store instructions\n";
        ss << "Instrumented tracking to " << stack_store_instr_cnt << 
            " stack store instructions\n";
        ss << "Instrumented tracking to " << store_const_global_cnt << 
            " store const global instructions\n";
        LOG(LVL_INFO) << ss.str();
        return false;
    }

};
}





char HeapExpoGlobalTracker::ID = 1;
char HeapExpoFuncTracker::ID = 2;
static RegisterPass<HeapExpoGlobalTracker> X("HeapExpoGlobal", "HeapExpo Global Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
static RegisterPass<HeapExpoFuncTracker> Y("HeapExpoFunc", "HeapExpo Function Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);

static void registerMyPass(const PassManagerBuilder &,
                           legacy::PassManagerBase &PM) {
    PM.add(new HeapExpoFuncTracker());
    PM.add(new HeapExpoGlobalTracker());
}

static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_OptimizerLast,
            registerMyPass);

static RegisterStandardPasses
    RegisterMyPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
            registerMyPass);
