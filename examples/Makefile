CC=clang
HECC=../heap-expo-clang

TEST_PROGS = global_uaf heap_uaf stack_uaf dangling stack_func_uaf stack_var_unused

all: $(TEST_PROGS)

%:%.c
	$(HECC) -g $< -o $@  

PASS_MSG = [HeapExpo][Test] Passed
FAIL_MSG = [HeapExpo][Test] Failed

test:
	@./global_uaf || if [ $$? = 139 ]; then echo $(PASS_MSG); else echo $(FAIL_MSG) ; fi
	@./heap_uaf   || if [ $$? = 139 ]; then echo $(PASS_MSG); else echo $(FAIL_MSG) ; fi
	@./stack_uaf  || if [ $$? = 139 ]; then echo $(PASS_MSG); else echo $(FAIL_MSG) ; fi
	@./dangling   || if [ $$? = 99 ]; then echo $(PASS_MSG); else echo $(FAIL_MSG) ; fi

clean:
	rm -f $(TEST_PROGS)
