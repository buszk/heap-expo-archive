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

TEST_PROGS  = list-test shadow-test

PROGS       = heap-expo-clang LLVMHeapExpo.so heap-expo-rt.o heap-expo-rt-32.o heap-expo-rt-64.o afl-heap-expo-map $(TEST_PROGS)

PASS_CFL    = -Xclang -load -Xclang ./LLVMHeapExpo.so $(LTOFLAG)

all: $(PROGS)

heap-expo-clang: heap-expo-clang.cpp
	$(CXX) $(CXXFLAGS) $(CXXLTOFLAG) $< -o $@ 
	ln -sf heap-expo-clang heap-expo-clang++

LLVMHeapExpo.so: heap-expo-pass.cpp
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

afl-heap-expo-map: afl-heap-expo-map.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ -Iinclude

heap-expo-rt.o: heap-expo-rt.o.cpp 
	$(CXX) $(CXXFLAGS) $(RTFLAGS) -fPIC -c $< -o $@
	$(CXX) $(CXXFLAGS) $(RTFLAGS) $(MTFLAG) -fPIC -c $< -o $(@:.o=-mt.o)

heap-expo-rt-32.o: heap-expo-rt.o.cpp
	@printf "[*] Building 32-bit variant of the runtime (-m32)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) $(MTFLAG) -m32 -fPIC -c $< -o $(@:.o=-mt.o) 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

heap-expo-rt-64.o: heap-expo-rt.o.cpp
	@printf "[*] Building 64-bit variant of the runtime (-m64)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) $(MTFLAG) -m64 -fPIC -c $< -o $(@:.o=-mt.o) 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

shadow-test: shadow-test.cpp include/shadow.h
	$(CXX) -g -O0 $(RTFLAGS) $< -o $@

list-test: list-test.cpp include/rt-stl.h
	$(CXX) -g -O0 $(RTFLAGS) $< -o $@

test: test_shadow test_list test_build test_time

test_shadow:
	./shadow-test
	@echo "[*] Shadow memory test passed"

test_list:
	./list-test
	@echo "[*] Sorted list test passed"

test_build: $(PROGS)
	@echo "[*] Building with clang wrapper"
	./heap-expo-clang ./test-instr.c -o test-instr 2>/dev/null
	./heap-expo-clang -O3 ./test-instr.c -o test-instr 2>/dev/null
	./heap-expo-clang++ ./test-instr-cxx.cpp -o test-instr-cxx 2>/dev/null
	./heap-expo-clang++ -O3 ./test-instr-cxx.cpp -o test-instr-cxx 2>/dev/null
	@echo "[*] Building with clang wrapper success"

test_time: $(PROGS)
	@echo "[*] Analyzing compiler wrapper overhead (along with AFL)"
	@d=$$(date +%s%N); \
	clang ./test-instr.c -o /dev/null -O3 2>/dev/null; \
	b=$$(($$(date +%s%N)-d)); \
	d=$$(date +%s%N); \
	HEAP_EXPO_CC=/home/zekun/repo/afl-2.52b/afl-clang-fast ./heap-expo-clang ./test-instr.c -o /dev/null -O3 2>/dev/null; \
	t=$$(($$(date +%s%N)-d)); \
	echo "Overhead for compiling test-instr.c is $$((100*t/b))%, base is $$((b)), our compiler takes $$((t))"
	
	@d=$$(date +%s%N); \
	clang++ ./test-instr-cxx.cpp -o /dev/null -O3 2>/dev/null; \
	b=$$(($$(date +%s%N)-d)); \
	d=$$(date +%s%N); \
	AFL_CXX=./heap-expo-clang++ /home/zekun/repo/afl-2.52b/afl-clang-fast++ -g ./test-instr-cxx.cpp -o /dev/null -O3 2>/dev/null; \
	t=$$(($$(date +%s%N)-d)); \
	echo "Overhead for compiling test-instr-cxx.cpp is $$((100*t/b))%, base is $$((b)), our compiler takes $$((t))"

clean:
	rm -f $(PROGS) ./test-instr ./test-instr-cxx ./heap-expo-clang++
