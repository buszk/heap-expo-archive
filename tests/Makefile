CXX = clang++

RTFLAGS     = -I../include -g -O0

TEST_PROGS  = list-test shadow-test

all: $(TEST_PROGS)

shadow-test: shadow-test.cpp ../include/shadow.h
	$(CXX) $(RTFLAGS) $< -o $@

list-test: list-test.cpp ../include/rt-stl.h
	$(CXX) $(RTFLAGS) $< -o $@

test: test_shadow test_list test_build test_time

test_shadow: shadow-test
	./shadow-test
	@echo "[*] Shadow memory test passed"

test_list: list-test
	./list-test
	@echo "[*] Sorted list test passed"

test_build: 
	@echo "[*] Building with clang wrapper"
	../heap-expo-clang ./test-instr.c -o test-instr 2>/dev/null
	../heap-expo-clang -O3 ./test-instr.c -o test-instr 2>/dev/null
	../heap-expo-clang++ ./test-instr-cxx.cpp -o test-instr-cxx 2>/dev/null
	../heap-expo-clang++ -O3 ./test-instr-cxx.cpp -o test-instr-cxx 2>/dev/null
	@echo "[*] Building with clang wrapper success"

test_time:
	@echo "[*] Analyzing compiler wrapper overhead (along with AFL)"
	@d=$$(date +%s%N); \
	clang ./test-instr.c -o /dev/null -O3 2>/dev/null; \
	b=$$(($$(date +%s%N)-d)); \
	d=$$(date +%s%N); \
	HEAP_EXPO_CC=/home/zekun/repo/afl-2.52b/afl-clang-fast ../heap-expo-clang ./test-instr.c -o /dev/null -O3 2>/dev/null; \
	t=$$(($$(date +%s%N)-d)); \
	echo "Overhead for compiling test-instr.c is $$((100*t/b))%, base is $$((b)), our compiler takes $$((t))"
	
	@d=$$(date +%s%N); \
	clang++ ./test-instr-cxx.cpp -o /dev/null -O3 2>/dev/null; \
	b=$$(($$(date +%s%N)-d)); \
	d=$$(date +%s%N); \
	AFL_CXX=../heap-expo-clang++ /home/zekun/repo/afl-2.52b/afl-clang-fast++ -g ./test-instr-cxx.cpp -o /dev/null -O3 2>/dev/null; \
	t=$$(($$(date +%s%N)-d)); \
	echo "Overhead for compiling test-instr-cxx.cpp is $$((100*t/b))%, base is $$((b)), our compiler takes $$((t))"
