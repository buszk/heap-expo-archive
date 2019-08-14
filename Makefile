CC  = clang-7
CXX = clang++-7
LLVM_CONFIG ?= llvm-config-7

CFLAGS     ?= -O2 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign 
CXXFLAGS   ?= -O2 -funroll-loops
CXXFLAGS   += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
			 -Wno-variadic-macros -std=c++17

LD_FLAGS   += -rdynamic

LTOFLAG     = 
CXXLTOFLAG  =

RTFLAGS     = $(LTOFLAG) -Iinclude

MTFLAG      = -DMULTITHREADING

INST_LFL    = $(LDFLAGS) heap-expo-rt.o -lstdc++ # force c++ linker

CLANG_CFL   = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fpic $(CXXFLAGS) -Iinclude
CLANG_LFL   = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS)

PROGS       = heap-expo-clang LLVMHeapExpo.so heap-expo-rt.o heap-expo-rt-32.o heap-expo-rt-64.o afl-heap-expo-map shadow-test

PASS_CFL    = -Xclang -load -Xclang ./LLVMHeapExpo.so $(LTOFLAG)

all: $(PROGS) test_build

heap-expo-clang: heap-expo-clang.cpp
	$(CXX) $(CXXFLAGS) $(CXXLTOFLAG) $< -o $@ 
	ln -sf heap-expo-clang heap-expo-clang++

LLVMHeapExpo.so: heap-expo-pass.cpp
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

afl-heap-expo-map: afl-heap-expo-map.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ -Iinclude

heap-expo-rt.o: heap-expo-rt.o.cpp shadow.h
	$(CXX) $(CXXFLAGS) $(RTFLAGS) -fPIC -c $< -o $@
	$(CXX) $(CXXFLAGS) $(RTFLAGS) $(MTFLAG) -fPIC -c $< -o $(@:.o=-mt.o)

heap-expo-rt-32.o: heap-expo-rt.o.cpp shadow.h
	@printf "[*] Building 32-bit variant of the runtime (-m32)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) $(MTFLAG) -m32 -fPIC -c $< -o $(@:.o=-mt.o) 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi



heap-expo-rt-64.o: heap-expo-rt.o.cpp shadow.h
	@printf "[*] Building 64-bit variant of the runtime (-m64)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) $(MTFLAG) -m64 -fPIC -c $< -o $(@:.o=-mt.o) 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

shadow-test: shadow-test.cpp shadow.h
	$(CXX) -g -O0 $(RTFLAGS) $< -o $@

test_shadow:
	./shadow-test

test_build: $(PROGS)
	./heap-expo-clang ./test-instr.c -o test-instr
	./heap-expo-clang -O3 ./test-instr.c -o test-instr
	./heap-expo-clang++ ./test-instr-cxx.cpp -o test-instr-cxx
	./heap-expo-clang++ -O3 ./test-instr-cxx.cpp -o test-instr-cxx

test_time: $(PROGS)
	@d=$$(date +%s%N); \
	clang ./test-instr.c -o /dev/null -O3; \
	b=$$(($$(date +%s%N)-d)); \
	d=$$(date +%s%N); \
	HEAP_EXPO_CC=/home/zekun/repo/afl-2.52b/afl-clang-fast ./heap-expo-clang ./test-instr.c -o /dev/null -O3; \
	t=$$(($$(date +%s%N)-d)); \
	echo "Overhead is $$((100*t/b))%, base is $$((b)), our compiler takes $$((t))"
	
	@d=$$(date +%s%N); \
	clang++ ./test-instr-cxx.cpp -o /dev/null -O3; \
	b=$$(($$(date +%s%N)-d)); \
	d=$$(date +%s%N); \
	AFL_CXX=./heap-expo-clang++ /home/zekun/repo/afl-2.52b/afl-clang-fast++ -g ./test-instr-cxx.cpp -o /dev/null -O3; \
	t=$$(($$(date +%s%N)-d)); \
	echo "Overhead is $$((100*t/b))%, base is $$((b)), our compiler takes $$((t))"

clean:
	rm -f $(PROGS) ./test-instr ./test-instr-cxx ./heap-expo-clang++
