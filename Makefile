CC  = clang
CXX = clang++
LLVM_CONFIG = llvm-config

CFLAGS     ?= -O2 -funroll-loops
CFLAGS     += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign 
CXXFLAGS   ?= -O2 -funroll-loops
CXXFLAGS   += -Wall -D_FORTIFY_SOURCE=2 -g -Wno-pointer-sign \
			 -Wno-variadic-macros -std=c++14

LDFLAGS   += -rdynamic -ldl -lpthread

LTOFLAG     = 
CXXLTOFLAG  =

RTFLAGS     = $(LTOFLAG) -Iinclude -g 

MTFLAG      = -DMULTITHREADING

INST_LFL    = $(LDFLAGS) obj/heap-expo-rt.o -lstdc++ # force c++ linker

CLANG_CFL   = `$(LLVM_CONFIG) --cxxflags` -Wl,-znodelete -fno-rtti -fpic $(CXXFLAGS) -Iinclude
CLANG_LFL   = `$(LLVM_CONFIG) --ldflags` $(LDFLAGS) -fno-rtti

OBJS        = obj/heap-expo-rt.o obj/heap-expo-rt-32.o obj/heap-expo-rt-64.o 
PROGS       = heap-expo-clang LLVMHeapExpo.so afl-heap-expo-map $(OBJS) $(TEST_PROGS) 

PASS_CFL    = -Xclang -load -Xclang ./LLVMHeapExpo.so $(LTOFLAG)

all: $(PROGS)

heap-expo-clang: heap-expo-clang.cpp
	$(CXX) $(CXXFLAGS) $(CXXLTOFLAG) $(LDFLAGS) $< -o $@ 
	ln -sf heap-expo-clang heap-expo-clang++

LLVMHeapExpo.so: heap-expo-pass.cpp
	$(CXX) $(CLANG_CFL) -shared $< -o $@ $(CLANG_LFL)

afl-heap-expo-map: afl-heap-expo-map.cpp
	$(CXX) $(CXXFLAGS) $< -o $@ -Iinclude

obj/heap-expo-rt.o: heap-expo-rt.o.cpp 
	mkdir -p obj
	$(CXX) $(CXXFLAGS) $(RTFLAGS) -fPIC -c $< -o $@
	$(CXX) $(CXXFLAGS) $(RTFLAGS) $(MTFLAG) -fPIC -c $< -o $(@:.o=-mt.o)

obj/heap-expo-rt-32.o: heap-expo-rt.o.cpp
	mkdir -p obj
	@printf "[*] Building 32-bit variant of the runtime (-m32)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m32 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) $(MTFLAG) -m32 -fPIC -c $< -o $(@:.o=-mt.o) 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi

obj/heap-expo-rt-64.o: heap-expo-rt.o.cpp
	mkdir -p obj
	@printf "[*] Building 64-bit variant of the runtime (-m64)... "
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) -m64 -fPIC -c $< -o $@ 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi
	@$(CXX) $(CXXFLAGS) $(RTFLAGS) $(MTFLAG) -m64 -fPIC -c $< -o $(@:.o=-mt.o) 2>/dev/null; if [ "$$?" = "0" ]; then echo "success!"; else echo "failed (that's fine)"; fi


clean:
	rm -rf $(PROGS) obj ./heap-expo-clang++ 
