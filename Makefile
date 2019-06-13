CC  = clang-7
CXX = clang++-7
LLVM_CONFIG ?= llvm-config-7

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

CXXFLAGS   ?= -O3 -funroll-loops
CXXFLAGS   += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
			 -Wno-variadic-macros

RTFLAGS     = -flto

INST_LFL    = $(LDFLAGS) heap-expo-rt.o malloc-rt.o -lstdc++ # force c++ linker

CLANG_CFL   = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fpic $(CXXFLAGS) -Iinclude
CLANG_LFL   = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

PROGS       = LLVMHeapExpo.so heap-expo-rt.o malloc-rt.o

PASS_CFL    = -Xclang -load -Xclang ./LLVMHeapExpo.so -flto

all: $(PROGS) test_build

LLVMHeapExpo.so: heap-expo-pass.cpp
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

heap-expo-rt.o: heap-expo-rt.o.cpp
	$(CXX) $(CXXFLAGS) $(RTFLAGS) -fPIC -c $< -o $@ -Iinclude

malloc-rt.o: malloc-rt.o.cpp
	$(CXX) $(CXXFLAGS) $(RTFLAGS) -fPIC -c $< -o $@ -Iinclude

test_build: $(PROGS)
	$(CC) $(PASS_CFL) $(CFLAGS) $(INST_LFL) ./test-instr.c -o test-instr
	$(CXX) $(PASS_CFL) $(CXXFLAGS) $(INST_LFL) ./test-instr-cxx.cpp -o test-instr-cxx

clean:
	rm -f $(PROGS) ./test-instr
