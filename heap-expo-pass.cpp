#include "llvm/Pass.h"
#include "llvm/IR/Function.h"

#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Analysis/CFG.h"

#include "llvm-include.h"

#include <exception>
#include <cxxabi.h>
#include <sstream>
#include <sys/time.h>

#include <cstdlib>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

#include <vector>
#include <set>
#include <list>
#include <algorithm>

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
    /* Ctor priority */
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

/* 
 * Class for register all global variables in Module.
 * A global ctor function with global_hook functions is created
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
    
            /* Ignore constant jlobal variables */
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
       
        if (global_instr_cnt) {
            std::ostringstream ss;
            ss << "Instrumented tracking to " << global_instr_cnt << 
                " global variables\n";
            LOG(LVL_INFO) << ss.str();
        }
        return false;
    }

};

static bool isPotentiallyDefed(Instruction *To, std::set<Instruction*> &Defs) {
    for (Instruction *I : Defs) 
        if (isPotentiallyReachable(I, To))
            return true;
    return false;
}

static bool isPotentiallyUsed(Instruction *From, std::set<Instruction*> &Uses, std::set<Instruction*> &Defs) {

    /* Fast Path */
    if (Uses.size() == 0) {
        return false;
    }

    bool def_in_block = false;
    bool found_src = false;
    BasicBlock *p = (BasicBlock*)From->getParent();
    
    auto in_set = [](Instruction *I, std::set<Instruction*> Set) {
        return Set.find(I) != Set.end();
    };

    std::set<BasicBlock*> ToBlocks;
    std::set<BasicBlock*> AvoidBlocks;
    std::set<BasicBlock*> IntersectBlock;
    std::set<BasicBlock*> UseBlock;
    std::set<BasicBlock*> DefBlock;
   /* 
    LOG(LVL_DEBUG) << "==========================\n";
    LOG(LVL_DEBUG) << "Defs\n";
    for (Instruction* i : Defs) {
        LOG(LVL_DEBUG) << *i << "\n";
    }
    LOG(LVL_DEBUG) << "Uses\n";
    for (Instruction* i : Uses) {
        LOG(LVL_DEBUG) << *i << "\n";
    }
    */

    bool to_parent = false;

    for (auto i = p->begin(); i != p->end(); i++) {
        Instruction* I = (Instruction*) &*i;
        if (I == From) {
            //LOG(LVL_DEBUG) << "Found call\n";
            found_src = true;
        }
        else if (found_src && in_set(I, Defs)) {
            //LOG(LVL_DEBUG) << "Def after call\n";
            return false;
        }
        else if (found_src && in_set(I, Uses))  {
            //LOG(LVL_DEBUG) << "Use after call\n";
            return true;
        }
        else if (!found_src && in_set(I, Defs)) {
            //LOG(LVL_DEBUG) << "Found def in block before call\n";
            def_in_block = true;
        }
        else if (!found_src && in_set(I, Uses) && def_in_block) {
            //LOG(LVL_DEBUG) << "Found use in block before call but guarded by def\n";
            //remove_set(I, Uses);
        }
        else if (!found_src && in_set(I, Uses) && !def_in_block)  {
            //LOG(LVL_DEBUG) << "Found use in block before call and any def\n";
            to_parent = true;
        }
    }

    for (Instruction *I : Uses) {
        if (I->getParent() != p)
            UseBlock.insert((BasicBlock*)I->getParent());
    }
    for (Instruction *I : Defs) {
        if (I->getParent() != p)
            DefBlock.insert((BasicBlock*)I->getParent());
    }


    auto diff_set = [] (std::set<BasicBlock*> &s1, std::set<BasicBlock*> &s2, 
            std::set<BasicBlock*> &output) {

        for (BasicBlock *b : s1) 
            if (s2.find(b) == s2.end()) 
                output.insert(b);

    };

    diff_set(UseBlock, DefBlock, ToBlocks);
    diff_set(DefBlock, UseBlock, AvoidBlocks);

    auto inter_set = [] (std::set<BasicBlock*> &s1, std::set<BasicBlock*> &s2, 
            std::set<BasicBlock*> &output) {

        for (BasicBlock *b: s1)
            if (s2.find(b) != s2.end())
                output.insert(b);

    };
    inter_set (UseBlock, DefBlock, IntersectBlock);

    for (const BasicBlock *BB : IntersectBlock) {
        for (const Instruction &Ins : *BB) {
            Instruction* I = (Instruction*)&Ins;
            if (in_set(I, Uses)) {
                ToBlocks.insert((BasicBlock*)BB);
                break;
            }
            else if (in_set(I, Defs)) {
                AvoidBlocks.insert((BasicBlock*)BB);
                break;
            }
        }
    }
    /* Fast Path */
    if (ToBlocks.size() == 0 && !to_parent)
        return false;

    std::vector<BasicBlock*> Reached;
    std::set<BasicBlock*> WorkList;
    WorkList.insert((BasicBlock*)p);
    /*
    LOG(LVL_DEBUG) << "Avoid\n";
    for (BasicBlock* b: AvoidBlocks) {
        LOG(LVL_DEBUG) << *b << "\n";
    }
    LOG(LVL_DEBUG) << "To\n";
    for (BasicBlock* b: ToBlocks) {
        LOG(LVL_DEBUG) << *b << "\n";
    }
    */
    while(!WorkList.empty()) {

        BasicBlock *cur = *WorkList.begin();
        WorkList.erase(cur);
        Reached.push_back(cur);

        for (auto it = succ_begin(cur); it != succ_end(cur); it++) {

            BasicBlock *next = *it;
            if (AvoidBlocks.find(next) == AvoidBlocks.end() &&
                find(Reached.begin(), Reached.end(), next) == Reached.end())
                WorkList.insert(next);
 
            if (to_parent && next== (BasicBlock*)p) {
                return true;
            }

            if (ToBlocks.find(next) != ToBlocks.end()) {
                return true;
            }
        }
    }
    return false;

}

static AllocaInst* getStackPtr(Value *V) {

    User *U = dyn_cast<User>(V);

    if (U) {
    
        if (isa<AllocaInst>(U)) {
            return dyn_cast<AllocaInst>(U);
        }
        else if (isa<BinaryOperator>(U)) {

            if (getStackPtr(U->getOperand(0)))
                return getStackPtr(U->getOperand(0));
            if (getStackPtr(U->getOperand(1)))
                return getStackPtr(U->getOperand(1));

        }

    }

    return NULL;

}

static void logToFile(int fd, char* buf, int n) {
    
    if ( n < 0 ) {
        LOG(LVL_WARNING) << "sprintf failed\n";
        return;
    }
    if (fd < 0) {
        LOG(LVL_WARNING) << "fd not setup\n";
        return;
    } 
    if (n != write(fd, buf, n)) 
        return;
    
}

static void logID(int fd, DebugLoc DLoc, uint32_t cur_call) {

    int n;
    char buf[256];

    if (!DLoc || !DLoc.getScope())
        return;

    DIScope *scp = cast<DIScope>(DLoc.getScope());

    std::string fname = scp->getFilename();
    n = sprintf(buf, "%08x: %s:%d\n", cur_call, fname.c_str(), DLoc.getLine());

    logToFile(fd, buf, n);

}

static void logVarID(int fd, DIVariable *V, uint32_t cur_call) {

    int n;
    char buf[256];

    if (!V) return;

    std::string fname =  V->getFilename();
    std::string vname = V->getName();
    n = sprintf(buf, "%08x: %s:%d [%s]\n", cur_call,
            fname.c_str(), V->getLine(), vname.c_str());

    logToFile(fd, buf, n);

}

/*
 * Base function for our pointer tracker classes
 * Provide functionalities of instrumenting HeapExpo functions
 */
struct HeapExpoFuncTracker : public FunctionPass  {
    bool initialized;
    Module *M;
    Function *regptr, *deregptr, *stack_regptr;
    Function *voidcallstack, *checkstackvar;
    Function *Func;
    size_t store_instr_cnt = 0;
    size_t stack_store_instr_cnt = 0;
    size_t store_const_global_cnt = 0;
    int fd;
    

    HeapExpoFuncTracker(char ID) : FunctionPass(ID) {
        initialized = false;
    }

    void instrDereg(StoreInst *SI) {

        DebugLoc DLoc = SI->getDebugLoc();
        if (!DLoc) 
            DLoc = DebugLoc::get(0, 0, (MDNode*)Func->getSubprogram());
        
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

        logID(fd, DLoc, cur_call);

    }

    void instrReg(StoreInst *SI) {

        DebugLoc DLoc = SI->getDebugLoc();
        if (!DLoc)
            DLoc = DebugLoc::get(0, 0, (MDNode*)Func->getSubprogram());
       
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

        logID(fd, DLoc, cur_call);
    }
    
    void instrStackReg(StoreInst *SI) {

        DebugLoc DLoc = SI->getDebugLoc();
        if (!DLoc)
            DLoc = DebugLoc::get(0, 0, (MDNode*)Func->getSubprogram());
       
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
        CallInst *stack_regptr_call = CallInst::Create(stack_regptr, Args, "");
        stack_regptr_call->insertBefore(SI);
        stack_regptr_call->setDebugLoc(DLoc);

        logID(fd, DLoc, cur_call);
    }

    void instrVoid(CallInst *CI) {
        
        DebugLoc DLoc = CI->getDebugLoc();
        if (!DLoc)
            DLoc = DebugLoc::get(0, 0, (MDNode*)Func->getSubprogram());

        CallInst *voidcallstack_call = CallInst::Create(voidcallstack, {}, "");
        voidcallstack_call->insertAfter(CI);
        voidcallstack_call->setDebugLoc(DLoc);

    }

    void instrCheck(CallInst *CI, AllocaInst *AI, DIVariable *V) {
        
        uint32_t cur_call = rand() & 0xffffffff;

        DebugLoc DLoc = CI->getDebugLoc();
        if (!DLoc)
            DLoc = DebugLoc::get(0, 0, (MDNode*)Func->getSubprogram());

        ConstantInt *CurCall = ConstantInt::get(Int32Ty(M), cur_call);

        CastInst *cast_loc =
            CastInst::CreatePointerCast(AI, Int8PtrTy(M));
        std::vector <Value*> Args;
        Args.push_back(cast_loc);
        Args.push_back(CurCall);
        CallInst *checkstackvar_call = CallInst::Create(checkstackvar, Args, "");
        cast_loc->insertAfter(CI);
        cast_loc->setDebugLoc(DLoc);
        LOG(LVL_DEBUG) << "checkstackvar\n";
        checkstackvar_call->insertAfter(cast_loc);
        checkstackvar_call->setDebugLoc(DLoc);
        
        logID(fd, DLoc, cur_call);
        logVarID(fd, V, cur_call);

    }


    
    void initialize(Module *M) { 

        Constant *deregptr_def = M->getOrInsertFunction("deregptr", VoidTy(M), Int8PtrTy(M), Int32Ty(M));
        deregptr = cast<Function>(deregptr_def);
        deregptr->setCallingConv(CallingConv::C);
        
        Constant *regptr_def = M->getOrInsertFunction("regptr", VoidTy(M), Int8PtrTy(M), Int8PtrTy(M), Int32Ty(M));
        regptr = cast<Function>(regptr_def);
        regptr->setCallingConv(CallingConv::C);
        
        Constant *stack_regptr_def = M->getOrInsertFunction("stack_regptr", VoidTy(M), Int8PtrTy(M), Int8PtrTy(M), Int32Ty(M));
        stack_regptr = cast<Function>(stack_regptr_def);
        stack_regptr->setCallingConv(CallingConv::C);
        
        Constant *voidcallstack_def = M->getOrInsertFunction("voidcallstack", VoidTy(M));
        voidcallstack = cast<Function>(voidcallstack_def);
        voidcallstack->setCallingConv(CallingConv::C);

        Constant *checkstackvar_def = M->getOrInsertFunction("checkstackvar", VoidTy(M), Int8PtrTy(M), Int32Ty(M));
        checkstackvar = cast<Function>(checkstackvar_def);
        checkstackvar->setCallingConv(CallingConv::C);

        struct timeval time;
        gettimeofday(&time, NULL);
        srand((time.tv_sec*1000) + (time.tv_usec/1000));
        
        fd = open("store_inst.log", O_WRONLY | O_CREAT | O_APPEND, 0600);
        
        initialized = true;

    }

    virtual bool runOnFunction(Function &F) = 0;

    virtual bool doFinalization(Module &Mod) {
        std::ostringstream ss;
        if (store_instr_cnt)
            ss << "Instrumented tracking to " << store_instr_cnt << 
                " all store instructions\n";
        if (stack_store_instr_cnt)
            ss << "Instrumented tracking to " << stack_store_instr_cnt << 
                " stack store instructions\n";
        if (store_const_global_cnt)
            ss << "Instrumented tracking to " << store_const_global_cnt << 
                " store const global instructions\n";
        LOG(LVL_INFO) << ss.str();

        close(fd);

        return false;
    }

};

/* 
 * Helper class for call graph analysis
 * We conservatively anlysis if a call instr would free any claimed dynamic mem
 */
struct CallGraphAnalysis {
    std::set<std::string> external;
    std::set<std::string> may_free = {"free", "realloc", "_ZdlPv", "_ZdaPv"};
    std::set<std::string> not_free = {"malloc", "_Znwm", "calloc"};
    std::list<Function*> calls;

    bool has_free_call(Function *F) {
        
        if (!F) return true;
        
        std::string fname = F->getName();

        for (Function *Func : calls)
            if (F == Func) {
                return false;
            }

        if (may_free.find(fname) != may_free.end()) {
            return true;
        }
        if (not_free.find(fname) != not_free.end()) {
            return false;
        }
        if (external.find(fname) != external.end()) {
            return true;
        }

        /* External function */
        if (F->empty()) {
            if (fname == "regptr"|| fname == "deregptr" ||
                fname == "stack_regptr" || fname == "global_hook" ||
                fname == "voidcallstack" || fname == "checkstackvar")
                return false;
            if (fname.find("llvm.") == 0 ||
                fname.find("clang.") == 0)
                return false;
            external.insert(fname);
            return true;
        }

        calls.push_back(F);
        for (BasicBlock &B : *F) 
            for (Instruction &Ins : B)  {
                Instruction *I = &Ins;
                if (isa<CallInst>(I)) {
                    Function *CF = cast<CallInst>(I)->getCalledFunction();
                    if (F != CF)
                        if (has_free_call(CF))  {

                            may_free.insert(fname);
                            calls.pop_back();
                            return true;
                        }
                }
            }


        calls.pop_back();
        not_free.insert(fname);
        return false;
    }
};

/*
 * A simple class used to show result of Call Graph Analysis
 */
struct HeapExpoCallGraphAnalysis: public FunctionPass, public CallGraphAnalysis {
    static char ID;

    HeapExpoCallGraphAnalysis (): FunctionPass(ID) {}


    virtual bool runOnFunction(Function &Func) {

        Function *F = &Func;
        LOG(LVL_INFO) << F->getName() << " " << has_free_call(F) << "\n";

        return false;
    }

};


/* 
 * Class that examines important local pointer variables 
 * And register them to suppress them from lift to LLVM reg
 */
struct HeapExpoStackTracker : public HeapExpoFuncTracker, public CallGraphAnalysis {
    static char ID;
    std::set<AllocaInst*> stack_ptrs;
    std::map<AllocaInst*, DIVariable*> stack_vars;
    std::vector<CallInst*> calls_to_instr;
    std::map<AllocaInst*, std::vector<StoreInst*>> stores_to_instr;
    std::map<AllocaInst*, std::set<Instruction*>> defs;
    std::map<AllocaInst*, std::set<Instruction*>> uses;
    
    HeapExpoStackTracker () : HeapExpoFuncTracker(ID) {}
    
    virtual bool runOnFunction(Function &F) {

        LOG(LVL_DEBUG) << "HeapExpo: ";
        LOG(LVL_DEBUG).write_escaped(demangleName(F.getName())) << '\n';
        
        if (M != F.getParent()) {
            M = F.getParent();
            initialized = false;
        }


        if (!initialized) 
            initialize(M);

        Func = &F;
        for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {
            Instruction *I = &*i;
            if (isa<StoreInst> (I)) {
                LOG(LVL_DEBUG) << "Store instruction: " << *I << "\n";
                StoreInst *SI = dyn_cast<StoreInst> (I);

                
                if (SI->getValueOperand()->getType()->isPointerTy()) {
                
                    AllocaInst *AI = getStackPtr(SI->getPointerOperand());
                    if (AI)  {

                        defs[AI].insert(I);
                        stack_ptrs.insert(AI);

                        if (isa<ConstantPointerNull>(SI->getValueOperand())) {
                            LOG(LVL_DEBUG) << "Value is a nullptr\n";
                            //stack_store_instr_cnt ++;
                        } 
                        else  {
                            LOG(LVL_DEBUG) << "Value is a ptr\n";
                            stores_to_instr[AI].push_back(SI);
                        }

                    }
                }
            }
            else if (isa<LoadInst> (I)) {

                LoadInst *LI = dyn_cast<LoadInst> (I);

                AllocaInst *AI = getStackPtr(LI->getPointerOperand());
                if (AI && AI->getAllocatedType()->isPointerTy())  {
                    uses[AI].insert(I);
                    stack_ptrs.insert(AI);
                }

                

            }
            else if (isa<CallInst> (I)) {

                CallInst *CI = dyn_cast<CallInst> (I);

                if (!CI) continue;

                Function *F = CI->getCalledFunction();
                if (!F) continue;


                StringRef fname = F->getName();

                /* 
                 * No InstrinsicInst Class
                 * Use function name to detect intrinsic functions
                 */
                if (F->getName().find("llvm.") == 0 || 
                    F->getName().find("clang.") == 0) {

                    /* Use declare instrinsic to Hook AllocaInst with DIVariable */
                    if (fname == "llvm.dbg.declare") {
                        
                        AllocaInst *AI = nullptr;
                        DIVariable  *V = nullptr;
                        Metadata *meta0 = cast<MetadataAsValue>(CI->getOperand(0))->getMetadata();
                        if (isa<ValueAsMetadata>(meta0))  {
                            Value *v0 = cast<ValueAsMetadata>(meta0)->getValue();
                            if (isa<AllocaInst>(v0)) {
                                AI = cast<AllocaInst>(v0);
                            }
                        }

                        Metadata *meta1 = cast<MetadataAsValue>(CI->getOperand(1))->getMetadata();
                        if (isa<DIVariable>(meta1))
                            V = cast<DIVariable>(meta1);

                        if (AI && V) {
                            stack_vars[AI] = V;
                        }
                    }

                    continue;
                } 

                if (fname == "regptr" || fname == "deregptr" ||
                    fname == "voidcallstack" || fname == "checkstackvar")
                    continue;

                /* A call with stack var addr is considered a Def */
                for (Value *V : CI->arg_operands()) {

                    AllocaInst *AI = getStackPtr(V);

                    if (AI)
                        defs[AI].insert(I);

                }

                if (has_free_call(F))
                    calls_to_instr.push_back(CI);

            }

        }


        std::set<AllocaInst*> aset;
        for (CallInst *CI : calls_to_instr) {

            bool v = false;
            
            for (AllocaInst *AI: stack_ptrs) {
                if (isPotentiallyDefed(CI, defs[AI]) &&
                        isPotentiallyUsed(CI, uses[AI], defs[AI])) {

                    instrCheck(CI, AI, stack_vars[AI]);
                    aset.insert(AI);
                    v = true;
                }
            }
            if (v) instrVoid(CI);
        }

        int num = 0;
        for (AllocaInst* AI : aset) {
            num += defs[AI].size();
            for (StoreInst* SI: stores_to_instr[AI]) {
                instrStackReg(SI);
                stack_store_instr_cnt++;
            }
        }

        stack_ptrs.clear();
        uses.clear();
        defs.clear();
        calls_to_instr.clear();
        return false;

    }

};

/*
 * Class for register Heap pointers on .data and .heap sections
 * regptr and deregptr inserted to track propagation to these sections
 */
struct HeapExpoHeapTracker : public HeapExpoFuncTracker {
    static char ID;

    HeapExpoHeapTracker (): HeapExpoFuncTracker(ID) {
        
    }

    virtual bool runOnFunction(Function &F) {

        Func = &F;
        if (M != F.getParent())
            M = F.getParent();

        if (!initialized) 
            initialize(M);

        for (inst_iterator i = inst_begin(F), e = inst_end(F); i != e; i++) {

            Instruction *I = &*i;

            if (isa<StoreInst> (I))  {

                StoreInst *SI = cast<StoreInst> (I);

                if (SI->getValueOperand()->getType()->isPointerTy()) {
                    
                    if (!getStackPtr(SI->getPointerOperand())) {

                        if (isa<GlobalVariable>(SI->getPointerOperand()))
                            LOG(LVL_DEBUG) << "Storing to global var\n" ;
                            
                        if (isa<Constant>(SI->getValueOperand())) {
                            store_const_global_cnt++;
                            continue;
                        }

                        if (isa<ConstantPointerNull>(SI->getValueOperand())) {
                            store_instr_cnt ++;
                            instrDereg(SI);

                        }
                        else {

                            store_instr_cnt ++;
                            instrReg(SI);

                        }

                        SI->setVolatile(true);
                    }
                }
            }
            else if (isa<LoadInst> (I)) {
                LoadInst *LI = cast<LoadInst> (I);
    
                if (LI->getPointerOperandType()->isPointerTy()) {
                    if (!getStackPtr(LI->getPointerOperand())) {
                        LI->setVolatile(true);
                    }
                }

            }

        }
        return false;
    }
    
};

}





char HeapExpoGlobalTracker::ID = 1;
char HeapExpoHeapTracker::ID = 2;
char HeapExpoStackTracker::ID = 3;
char HeapExpoCallGraphAnalysis::ID = 4;

static RegisterPass<HeapExpoGlobalTracker> X("HeapExpoGlobal", "HeapExpo Global Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
static RegisterPass<HeapExpoHeapTracker> Y("HeapExpoHeap", "HeapExpo Heap Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
static RegisterPass<HeapExpoStackTracker> Z("HeapExpoStack", "HeapExpo Stack Pass",
                             false /* Only looks at CFG */,
                             false /* Analysis Pass */);
static RegisterPass<HeapExpoCallGraphAnalysis> W("HeapExpoCallGraph", "HeapExpo Call Graph Analysis",
                             false /* Only looks at CFG */,
                             true  /* Analysis Pass */);

static void registerMyPass(const PassManagerBuilder &,
                           legacy::PassManagerBase &PM) {
    PM.add(new HeapExpoGlobalTracker());
    //PM.add(new HeapExpoHeapTracker());
}

static void registerMyPassEarly(const PassManagerBuilder &,
        legacy::PassManagerBase &PM) {
    PM.add(new HeapExpoStackTracker());
    PM.add(new HeapExpoHeapTracker());
    
    //PM.add(new HeapExpoCallGraphAnalysis());
}

/* EarlyAsPossible is enabled with opt level 0 */
static RegisterStandardPasses
    RegisterMyPassEarly(PassManagerBuilder::EP_EarlyAsPossible,
            registerMyPassEarly);

static RegisterStandardPasses
    RegisterMyPass(PassManagerBuilder::EP_OptimizerLast,
            registerMyPass);

static RegisterStandardPasses
    RegisterMyPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
            registerMyPass);
