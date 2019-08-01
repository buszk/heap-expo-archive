CC=clang
HECC=../heap-expo-clang

TEST_PROGS = global_uaf heap_uaf stack_uaf dangling stack_func_uaf

all: $(TEST_PROGS)

%:%.c
	$(HECC) -g $< -o $@  -O2

clean:
	rm -f $(TEST_PROGS)
