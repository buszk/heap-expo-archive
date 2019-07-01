#if __x86_64__
#define SizeTy(x)       Type::getInt64Ty(x->getContext())
#else
#define SizeTy(x)       Type::getInt32Ty(x->getContext())
#endif

#define VoidTy(x)       Type::getVoidTy(x->getContext())
#define Int1Ty(x)       Type::getInt1Ty(x->getContext())
#define Int8Ty(x)       Type::getInt8Ty(x->getContext())
#define Int16Ty(x)      Type::getInt16Ty(x->getContext())
#define Int32Ty(x)      Type::getInt32Ty(x->getContext())
#define Int64Ty(x)      Type::getInt64Ty(x->getContext())
#define IntNTy(x, n)    Type::getIntNTy(x->getContext(), n)
#define Int1PtrTy(x)    Type::getInt1PtrTy(x->getContext())
#define Int8PtrTy(x)    Type::getInt8PtrTy(x->getContext())
#define Int16PtrTy(x)   Type::getInt16PtrTy(x->getContext())
#define Int32PtrTy(x)   Type::getInt32PtrTy(x->getContext())
#define Int64PtrTy(x)   Type::getInt64PtrTy(x->getContext())
#define IntNPtrTy(x, n) Type::getIntNPtrTy(x->getContext(), n)
