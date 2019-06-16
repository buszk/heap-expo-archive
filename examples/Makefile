CC=clang
HECC=../heap-expo-clang

TEST_PROGS = global_uaf heap_uaf stack_uaf

all: $(TEST_PROGS)

%:%.c
	$(HECC) -g $< -o $@
