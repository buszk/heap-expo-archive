CC  = clang-7
CXX = clang++-7
LLVM_CONFIG ?= llvm-config-7

CFLAGS     ?= -O3 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign

CXXFLAGS   ?= -O3 -funroll-loops
CXXFLAGS   += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
			 -Wno-variadic-macros

RTFLAGS     = -flto -Iinclude

INST_LFL    = $(LDFLAGS) heap-expo-rt.o malloc-rt.o -lstdc++ # force c++ linker

CLANG_CFL   = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fpic $(CXXFLAGS) -Iinclude
CLANG_LFL   = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

PROGS       = heap-expo-clang LLVMHeapExpo.so heap-expo-rt.o heap-expo-rt-32.o heap-expo-rt-64.o malloc-rt.o malloc-rt-32.o malloc-rt-64.o

PASS_CFL    = -Xclang -load -Xclang ./LLVMHeapExpo.so -flto

all: $(PROGS) test_build

heap-expo-clang: heap-expo-clang.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ 
	ln -sf heap-expo-clang heap-expo-clang++

LLVMHeapExpo.so: heap-expo-pass.cpp
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

heap-expo-rt.o: heap-expo-rt.o.cpp
	$(CXX) $(CXXFLAGS) $(RTFLAGS) -fPIC -c $< -o $@

heap-expo-rt-32.o: heap-expo-rt.o.cpp
	@printf "[*] Building 32-bit variant of the runtime (-m32)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

heap-expo-rt-64.o: heap-expo-rt.o.cpp
	@printf "[*] Building 64-bit variant of the runtime (-m64)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

malloc-rt.o: malloc-rt.o.cpp
	$(CXX) $(CXXFLAGS) $(RTFLAGS) -fPIC -c $< -o $@

malloc-rt-32.o: malloc-rt.o.cpp
	@printf "[*] Building 32-bit variant of the malloc runtime (-m32)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

malloc-rt-64.o: malloc-rt.o.cpp
	@printf "[*] Building 64-bit variant of the malloc runtime (-m64)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

test_build: $(PROGS)
	./heap-expo-clang ./test-instr.c -o test-instr
	./heap-expo-clang++ ./test-instr-cxx.cpp -o test-instr-cxx

clean:
	rm -f $(PROGS) ./test-instr ./test-instr-cxx
