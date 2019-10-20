CC=clang
HECC=../heap-expo-clang

CFLAGS ?=

TEST_PROGS = global_uaf heap_uaf stack_uaf dangling stack_func_uaf stack_var_unused realloc

all: $(TEST_PROGS)

%:%.c ../LLVMHeapExpo.so
	$(HECC) -g $(CFLAGS) $< -o $@  

PASS_MSG = [HeapExpo][Test] Passed
FAIL_MSG = [HeapExpo][Test] Failed

test:
	@./global_uaf || if [ $$? = 139 ]; then echo $(PASS_MSG); else echo $(FAIL_MSG) ; fi
	@./heap_uaf   || if [ $$? = 139 ]; then echo $(PASS_MSG); else echo $(FAIL_MSG) ; fi
	@./stack_uaf  || if [ $$? = 139 ]; then echo $(PASS_MSG); else echo $(FAIL_MSG) ; fi
	@HEXPO_STATUS=y ./dangling   || if [ $$? = 99 ]; then echo $(PASS_MSG); else echo $(FAIL_MSG) ; fi
	@RES=`./realloc 2>&1`; echo $$RES |grep reallocation;

clean:
	rm -f $(TEST_PROGS)
