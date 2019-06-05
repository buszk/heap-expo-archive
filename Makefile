CC  = clang-7
CXX = clang++-7

LLVM_CONFIG ?= llvm-config-7

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

CXXFLAGS   ?= -O3 -funroll-loops
CXXFLAGS   += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
			 -Wno-variadic-macros

CLANG_CFL   = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fpic $(CXXFLAGS)
CLANG_LFL   = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

PROGS       = LLVMHello.so

PASS_CFL    = -Xclang -load -Xclang ./LLVMHello.so

all: $(PROGS) test_build

LLVMHello.so: hello.cpp
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

test_build: $(PROGS)
	$(CC) $(PASS_CFL) $(CFLAGS) ./test-instr.c -o test-instr $(LDFLAGS)

clean:
	rm -f $(PROGS) ./test-instr
