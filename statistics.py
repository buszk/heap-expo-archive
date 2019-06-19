
import sys
def main():
    if len(sys.argv) < 2:
        print("Usage: %s <make_log>" % sys.argv[0])
        return 1
    
    with open(sys.argv[1]) as f:
        instr_str = "Instrumented tracking to "
        isntr_str_len = len(instr_str)
        store_str = "all store instructions"
        store_cnt = 0
        global_str = "global variables"
        global_cnt = 0
        stack_store_str = "stack store instructions"
        stack_store_cnt = 0
        for line in f:
            ind_1 = line.find(instr_str)
            if ind_1 >= 0:
                line = line[ind_1 + len(instr_str):]
                ind_2 = line.find(store_str)
                if ind_2 >= 0:
                    line = line[:ind_2]
                    store_cnt += int(line)
                ind_3 = line.find(global_str)
                if ind_3 >= 0:
                    line = line[:ind_3]
                    global_cnt += int(line)
                ind_4 = line.find(stack_store_str)
                if ind_4 >= 0:
                    line = line[:ind_4]
                    stack_store_cnt += int(line)
        print("all store count:", store_cnt)
        print("stack store count:", stack_store_cnt)
        print("global count:", global_cnt)


if __name__ == "__main__":
    main()
