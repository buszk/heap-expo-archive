#define HEAP_EXPO_RT
#define memcpy __memcpy
#include <cstdio>
#include <map>
#include <set>
#include <unordered_map>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>

#define UNW_LOCAL_ONLY
#if __x86_64__
#include <libunwind.h>
#else
#include <libunwind-x86.h>
#endif
#include <execinfo.h>
#include <link.h>
#include <dlfcn.h>

#include <stdio.h>
#include <execinfo.h>
#include <stdlib.h>

#include "rt-malloc.h"
#include "rt-include.h"
#include "shadow.h"
#include "hash.h"


/*
 * LVL0: Production
 * LVL1: Debug version, need to set env HEAP_EXPO_DEBUG
 * LVL2: Debug version
 */
#define DEBUG_LVL 1
#if DEBUG_LVL >= 1
#define PRINTF(...) __printf(__VA_ARGS__)
#else
#define PRINTF(...) 
#endif

#define ESP_ST static

using namespace std;

#define AFL
#define CATCHERRORS

#ifdef AFL
#include "afl-include.h"
#include <fstream>
#include <sys/shm.h>
ESP_ST char  __heap_expo_initial[HE_MAP_SIZE];
ESP_ST char* __heap_expo_ptr = __heap_expo_initial;
#endif 

#ifdef CATCHERRORS
#include <signal.h>
#endif

#define push_back_it(list, elem) (list).insert((list.end()), (elem))
#ifdef DEBUG
#define erase_it(list, it) \
    int flag = true; \
    for (auto i = (list).begin(); i != (list).end(); i++) {\
        if (*it == *i) \
            flag = false; }\
    assert(!flag); \
    list.erase(it) 
#else 
#define erase_it(list, it)  (list).erase(it);
#endif

using motype = shadow<struct object_info_t>;
ESP_ST motype *memory_objects;

using prtype = shadow<struct pointer_info_t>;
//using prtype = he_unordered_map<uintptr_t, struct pointer_info_t>;
ESP_ST prtype *ptr_record; // Log all all ptrs and the object addr 

using sptype = he_sorted_list<stack_pointer_t, comp<stack_pointer_t>>;
ESP_ST thread_local sptype *stack_record = NULL;

using rtype = he_list<residual_pointer_t>;
ESP_ST thread_local rtype *residuals = NULL;
ESP_ST thread_local int64_t counter = 0;
ESP_ST int64_t residual_live_limit = 1000;

using s2dtype = he_unordered_map<uint32_t, uint32_t>;
ESP_ST s2dtype *sig2dbg;

#ifdef MULTITHREADING
//ESP_ST mutex obj_mutex;
//ESP_ST mutex ptr_mutex;
ESP_ST mutex sig_mutex;
#endif

/* STATISTICS */
size_t n_alloc = 0;
size_t n_dealloc = 0;

ESP_ST bool he_initialized = false;
ESP_ST int status = 0;


/* 
 * 0 for not initialized
 * 1 for no invalidation
 * 2 for all but realloc invalidation
 * 3 for all invalidation
 */
ESP_ST int invalidate_mode = 0;

ESP_ST int fdcopy = -1;
#if DEBUG_LVL == 1
/*
 * 0 for not initialized
 * 1 for no debug info
 * 2 for only essential info
 * 3 for all debug info
 */
ESP_ST int print_mode = 0; 
#endif

#if DEBUG_LVL >= 1
inline void __printf(int lvl, const char * format, ...) {
#if DEBUG_LVL == 1
    if (print_mode < lvl) return;
#endif

    /* Make a copy in case stderr got closed */
    int n1, n2, n3;
    char str[256] = {0};
    va_list args;
    n1 = 0;//snprintf(str, 19, "[%016lx]", pthread_self());
    va_start(args, format);
    n2 = vsnprintf(str+n1, 256-n1, format, args);
    va_end(args);
    if (!(n3 = write(fdcopy, str, n1+n2))) 
        abort();
}
#endif

EXT_C void msg(const char* str) {
#if DEBUG_LVL >=1
    __printf(3, str);
#endif
}

#ifdef CATCHERRORS
void segfault_sigaction(int signal, siginfo_t *si, void *arg)
{
    uintptr_t addr = (uintptr_t) si->si_addr;
    if ((addr & KADDR) == KADDR) {
        PRINTF(1, "[HeapExpo] Use-after-%s with %s ptr detected: %016lx\n", 
                (addr & RABIT) ? "reallocation": "deallocation", 
                (addr & STKBIT) ? "stack": "heap", addr);
    }
    else {
        PRINTF(1, "[HeapExpo] Unknown segfault: %016lx\n", addr);
    }
    //raise(SIGSEGV);
    char **messages = NULL;
    void *array[16];
    int size;
    size = backtrace(array, 12);
    messages = backtrace_symbols(array, size);
    for (int i = 0; i < size; i++) {
        printf("[bt] #%d %s ", i, messages[i]);
        fflush(stdout);

        int p = 0;
        while (messages[i][p] != '(' && messages[i][p] != ' '
                && messages[i][p] != 0)
            p++;
        char syscom[256];
        sprintf(syscom, "addr2line %p -e %.*s", array[i], p, messages[i]);
        if(system(syscom)) {}
    }
    exit(139);
}
#endif

void __heap_expo_shm() {

    char *id_str = getenv(HE_SHM_ENV_VAR);

    if (id_str) {
        uint32_t shm_id = atoi(id_str);

        __heap_expo_ptr = (char*)shmat(shm_id, NULL, 0);

        if (__heap_expo_ptr == (void*)-1) exit(1);

        __heap_expo_ptr[0] = 1;

    }
    
}

inline bool is_invalid(uintptr_t addr) {
    return ((addr & KADDR) == KADDR);
}


bool get_object_addr(uintptr_t, uintptr_t&, struct object_info_t *&);

EXT_C void global_hook(char* addr, size_t size) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)addr;
    PRINTF(3, "[HeapExpo][global]: ptr:%016lx size:%016lx\n", ptr, size);
    auto obj = (struct object_info_t*)__malloc(sizeof(struct object_info_t));
    *obj = object_info_t(ptr, size, GLOBAL);
    
    memory_objects->insert_range(ptr, size, obj);
    
}

inline void init_global_vars() {

    INT_MALLOC(memory_objects, motype); 
    
    INT_MALLOC(ptr_record, prtype);

    INT_MALLOC(sig2dbg, s2dtype);
    
    PRINTF(3, "STL objects initialized\n");

}

void __attribute__((constructor (1))) init_rt(void) {

    if (getenv("HEXPO_DEBUG"))
        print_mode = atoi(getenv("HEXPO_DEBUG"));

    /* Default to no log */
    if (print_mode <= 0 || print_mode > 3)
        print_mode = 1;

    if (getenv("HEXPO_INVALID"))
        invalidate_mode = atoi(getenv("HEXPO_INVALID"));

    /* Default to invalidate all but realloc residuals */
    if (invalidate_mode <=0 || invalidate_mode > 3)
        invalidate_mode = 2;

    if (getenv("HEXPO_LIMIT"))
        residual_live_limit = atoi(getenv("HEXPO_LIMIT"));

    /* Default to 1000 */
    if (residual_live_limit < 0)
        residual_live_limit = 1000;

    /* Copy stderr in case it's closed */
    fdcopy = dup(2);

    init_global_vars();

#ifdef CATCHERRORS
	struct sigaction sa;
	memset(&sa, 0, sizeof(struct sigaction));
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = segfault_sigaction;
	sa.sa_flags   = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
#endif

#ifdef AFL
    __heap_expo_shm();
#endif

    he_initialized = true;
}

void __attribute__((destructor (65535))) fini_rt(void) {

    //print_heap();
    /*
    if (stack_record)
        PRINTF(0, "Stack record max: %d\n", stack_record->max);
    PRINTF(0, "Allocation: %d, Deallocation: %d\n", n_alloc, n_dealloc);
    */
    /* 
     * These frees may cause double free. 
     * Sometimes they are freed before dtor
     */
    //__free(sig2dbg);
    //__free(ptr_record);
    //__free(memory_objects);
}

void __attribute__((destructor (0))) exit_with_code(void) {

    /* Quiet configure scripts that may use exist status */ 
    if (status && getenv("HEXPO_STATUS")) exit(status);

}

inline void report_dangling(residual_pointer_t &ptr) {

    PRINTF(2, "[HeapExpo][Dangling]: loc[%016lx], val[%016lx], src_sig[%08x], "
           "dst_sig[%08x], store_id[%08x], free_sig[%08x], counter_diff[%u]\n",
            ptr.loc, ptr.val, ptr.src_sig, ptr.dst_sig, ptr.store_id,
            ptr.free_sig, counter - ptr.counter);

    status = 99;

#ifdef AFL
    if (__heap_expo_ptr != __heap_expo_initial)
        __heap_expo_ptr[(ptr.store_id/8) % HE_MAP_SIZE] |= (1 << ptr.store_id % 8);
#endif

}

inline void check_residuals() {

    if (!residuals) {
        INT_MALLOC(residuals, rtype);
    }

    while (!residuals->empty() &&
            residuals->front().adj_cnt <= counter - residual_live_limit) {
        residual_pointer_t  ptr = residuals->front();
        uintptr_t src_addr;
        struct object_info_t *src_info;
        get_object_addr(ptr.loc, src_addr, src_info);

        /* Is loc still valid? Does value changed? */
        if (src_addr && *(uintptr_t*)ptr.loc == ptr.val) 
            report_dangling(ptr);

        residuals->pop_front();
    }
    
    counter++;

}

EXT_C void check_double_free(void *val_) {

    uintptr_t val = (uintptr_t)val_;

    if (is_invalid(val)) {
        PRINTF(1, "[HeapExpo] Double Free detected. Trying to free %x", val);
        status = 98;
        exit(status);
    }
}

inline void remove_from_residuals(uintptr_t loc) {

    if (!residuals)
        return;

    for (auto it  = residuals->begin(); it != residuals->end(); it++) {
        if (it->loc == loc) {
            residuals->erase(it);
            break;
        }
    }

}

inline void update_residual_loc(uintptr_t oldloc, uintptr_t newloc) {

    if (!residuals)
        return;

    for (auto it = residuals->begin(); it != residuals->end(); it++) {
        if (it->loc == oldloc) {
            it->loc = newloc;
            break;
        }
    }
}

inline void address2offset(uintptr_t *addrs, uintptr_t *offsets, int cnt) {
    for (int i = 0; i < cnt ; i++) {
        Dl_info info;
        if (dladdr((void*)addrs[i], &info) &&
                info.dli_fname != NULL && info.dli_fname[0] != '\0')  {
            int64_t diff = addrs[i] - (uintptr_t)info.dli_fbase;
            offsets[i] = diff;
        }
    }
}

/*
 * This function provides the same signature despite the addresses
 * that ASLR load the binary and libraries
 */
inline uint32_t get_signature() {
    /* ignore this func, hook, and malloc/free */
    int cnt = -3;
    int size = 8;
    void *addrs[8] = {0};
    void *offsets[8] = {0};
    uint32_t sig = 0;
    uint32_t res = 0;
    bool newsig = false;

    unw_cursor_t cursor;
    unw_context_t uc;
    unw_word_t ip;
    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);

    while (unw_step(&cursor) > 0 && cnt < size) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        if (++cnt >= 0) {
            addrs[cnt] = (void*)ip;
        }
    }

    sig = hash_addr_list((uintptr_t*)addrs, cnt);

    LOCK(sig_mutex);
    if (sig2dbg->find(sig) == sig2dbg->end()) {

        newsig = true;

        address2offset((uintptr_t*)addrs, (uintptr_t*)offsets, cnt);

        res = hash_addr_list((uintptr_t*)offsets, cnt);

        (*sig2dbg)[sig] = res;

    } else {

        res = sig2dbg->at(sig);

    }
    UNLOCK(sig_mutex);
    
    if (newsig && print_mode >= 2) {
        PRINTF(2, "SIG[%08x][%d]:\n", res, cnt);
        backtrace_symbols_fd(addrs, cnt, fdcopy);
    }

    return sig;
}

inline void alloc_hook_(uintptr_t ptr, size_t size, uint32_t sig) {
    n_alloc ++;
    /* Add heap object to memory_objects. Simple */
    auto obj = (struct object_info_t*)__malloc(sizeof(object_info_t));
    *obj = object_info_t(ptr, size, HEAP, sig);
    memory_objects->insert_range(ptr, size, obj);
}

/* XXX: unwind stack */
EXT_C void alloc_hook(char* ptr_, size_t size) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)ptr_;
    PRINTF(3, "[HeapExpo][alloc]: ptr:%016lx size:%016lx\n", ptr, size);
    if (ptr) {

        uint32_t sig = 0;
        if (print_mode > 1)
            sig = get_signature();
        
        alloc_hook_(ptr, size, sig);
        
    }
}

inline void dealloc_hook_(uintptr_t ptr, uint32_t free_sig, bool invalidate) {
    n_dealloc ++;
    struct object_info_t *obj = memory_objects->find(ptr);

    /* Not very likely but ptr may be allocated by other libraries */
    if (!obj) {
        return;
    }

    memory_objects->insert_range(obj->addr, obj->size, nullptr);

    PRINTF(3, "[HeapExpo][dealloc_sig]: Object %016lx:%016lx is allocated with signature %08lx\n", obj->addr, obj->size, obj->signature);

    rtype tmp; 
    /* Invalidate ptrs that point to this heap object */
    LOCK(obj->in_mutex);
    auto copy = obj->in_edges;
    obj->in_edges.clear();
    UNLOCK(obj->in_mutex);
    //for (uintptr_t ptr_loc: obj->in_edges) {
    for (uintptr_t ptr_loc: copy) {
        struct pointer_info_t *ptr_info = ptr_record->find(ptr_loc);
        if (!ptr_info) {
            PRINTF(3, "Cannot Find PTR[%016lx] in ptr_record\n", ptr_loc);
            assert(false && "cannot find ptr in ptr_record");
            continue;
        }

        if (ptr != ptr_info->dst_obj || ptr_loc != ptr_info->loc) {
            /* XXX: Some data structure incongruence here */
            erase_it(ptr_info->src_info->out_edges, ptr_info->src_it);
            ptr_record->insert(ptr_loc, nullptr);
            continue;
        }
        assert(ptr == ptr_info->dst_obj);
        
        uintptr_t cur_val = *(uintptr_t*)ptr_loc;

        if (cur_val != ptr_info->value) {

            struct object_info_t *src_obj_info = ptr_info->src_info;

            PRINTF(3, "PTR[%016lx] has unknown behavior\n", ptr_loc);
            PRINTF(3, "Record: value: %016lx src_obj:%016lx dst_obj:%016lx\n",
                    ptr_info->value, ptr_info->src_obj, ptr_info->dst_obj);
            PRINTF(3, "Current value: %016lx\n", cur_val);
            erase_it(src_obj_info->out_edges, (ptr_info->src_it));
            //__free(ptr_info);
            ptr_record->insert(ptr_loc, nullptr);

            continue;

        }
        
        /* Value did not change, set it to kernel space */
        if (invalidate)
            *(uintptr_t*)ptr_loc = ( cur_val | KADDR | (obj->copied ? RABIT: 0) | STKBIT ) - STKBIT; 

        PRINTF(3, "[HeapExpo][invalidate]: ptr_loc:%016lx value:%016lx\n", ptr_loc, ptr_info->value);
        tmp.push_back(residual_pointer_t(ptr_loc, *(uintptr_t*)ptr_loc,
                    ptr_info->src_info->signature, ptr_info->dst_info->signature,
                    free_sig, ptr_info->id, counter));

        ptr_info->invalid = true;
    }
    
    obj->in_edges.clear();
    //UNLOCK(obj->in_mutex);

    for (auto &p: tmp) 
        p.adj_cnt += tmp.size();

    if (!residuals) {
        INT_MALLOC(residuals, rtype);
    }

    residuals->merge(tmp, cntcmp);



    /* Erase ptrs in this heap object */
    for (uintptr_t ptr_loc: obj->out_edges) {
        struct pointer_info_t *ptr_info = ptr_record->find(ptr_loc);
        if (ptr_info->loc != ptr_loc)
            continue;
        PRINTF(3, "[HeapExpo][remove]: ptr_loc:%016lx obj:%016lx\n", ptr_loc, obj->addr);
        if (!ptr_info->invalid) {
            struct object_info_t *dst_obj_info = ptr_info->dst_info;
            LOCK(dst_obj_info->in_mutex);
            erase_it(dst_obj_info->in_edges, (ptr_info->dst_it));
            UNLOCK(dst_obj_info->in_mutex);
        }
        else {
            PRINTF(3, "[HeapExpo][remove_invalid]: ptr_loc:%016lx\n", ptr_loc);
            remove_from_residuals(ptr_loc);
        }
        //__free(ptr_info);
        ptr_record->insert(ptr_loc, nullptr);
    }


    obj->out_edges.clear();
    obj->released = true;

    if (stack_record) {
        for (auto &p: stack_record->list) {
            if (p.dst_info == obj && p.val == *(uintptr_t*)p.loc) {
                if (invalidate_mode > 1) {
                    *(uintptr_t*)p.loc |= (KADDR | (obj->copied ? RABIT: 0) | STKBIT); 
                    PRINTF(3, "[HeapExpo][invalidate_stack]: ptr_loc:%016lx value:%016lx\n", p.loc, p.val);

                }
            }
        }
    }

    //__free(obj);
    
   
}

/* XXX: unwind stack */
EXT_C void dealloc_hook(char* ptr_) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)ptr_;
    PRINTF(3, "[HeapExpo][dealloc]: ptr:%016lx\n", ptr);
    if (ptr) {
        uint32_t sig = 0;
        if (print_mode > 1)
            sig = get_signature();

        check_double_free((void*)ptr);

        
        
        dealloc_hook_(ptr, sig, invalidate_mode>1 );
        
        
    }
}

/* XXX: unwind stack */
EXT_C void realloc_hook(char* oldptr_, char* newptr_, size_t newsize) {
    /*
     * Three cases: oldptr is NULL, newptr is NULL, no input is NULL
     * Case 1: work as alloc
     * Case 2: work as dealloc (sometimes this is the case)
     * Case 3: Alloc, Copy ptrs to new home, Dealloc
     */
    if (!he_initialized) return;
    uintptr_t oldptr = (uintptr_t)oldptr_;
    uintptr_t newptr = (uintptr_t)newptr_;
    size_t offset = newptr - oldptr;
    uint32_t sig = 0;
    if (print_mode > 1)
        get_signature();
    PRINTF(3, "[HeapExpo][realloc]: oldptr:%016lx newptr:%016lx size:%016lx\n", oldptr, newptr, newsize);
    

    struct object_info_t *old_info = memory_objects->find(oldptr);
    if (offset == 0 && old_info && old_info && old_info->addr == oldptr) {
        assert(old_info->addr == newptr);
        size_t oldsize = old_info->size;
        /* Modify shadow memory as well */
        if (newsize > oldsize) {
            /* Expand: insert metadata */
            memory_objects->insert_range(oldptr+oldsize, newsize -oldsize, old_info);
        }
        else {
            /* Shrink: remove metadata */
            memory_objects->insert_range(oldptr+newsize, oldsize-newsize, nullptr);
        }
        old_info->size = newsize;
        return;
    }
    
    
    if (newptr && newsize)
        alloc_hook_(newptr, newsize, sig);
    struct object_info_t *new_info = memory_objects->find(newptr);

    //size_t oldsize = memory_objects[oldptr].size;

    if (newptr && oldptr && old_info) {
        /* Iterate every objects old object points to */
        for (uintptr_t ptr_loc: old_info->out_edges) {

            /* Update inedges */

            struct pointer_info_t *ptr_info = ptr_record->find(ptr_loc);
            if (ptr_info->loc != ptr_loc)
                continue;

            assert(ptr_info);
            
            /* 
             * Shrinked. Ignore ptrs outside range 
             * Must be checked before dereference the addr
             */
            if (ptr_loc >= oldptr + newsize) {
                PRINTF(3, "PTR[%016lx] is discarded while realloc to a smaller area\n", ptr_loc);
                if (!ptr_info->invalid) {
                    LOCK(ptr_info->dst_info->in_mutex);
                    erase_it(ptr_info->dst_info->in_edges, (ptr_info->dst_it));
                    UNLOCK(ptr_info->dst_info->in_mutex);
                }
                else {
                    remove_from_residuals(ptr_loc);
                }
                //__free(ptr_info);
                ptr_record->insert(ptr_loc, nullptr);
                continue;
            }

            uintptr_t cur_val = *(uintptr_t*)(ptr_loc+offset);

            /* If value changed, we don't move this ptr */
            if (!ptr_info->invalid && cur_val != ptr_info->value) {
                PRINTF(3, "PTR[%016lx] value has changed\n", ptr_loc);
                LOCK(ptr_info->dst_info->in_mutex);
                erase_it(ptr_info->dst_info->in_edges, (ptr_info->dst_it));
                UNLOCK(ptr_info->dst_info->in_mutex);
                //__free(ptr_info);
                ptr_record->insert(ptr_loc, nullptr);
                continue;
            }


            PRINTF(3, "MOVING %s PTR[%016lx] to %016lx, OFFSET:%016lx\n", 
                    ptr_info->invalid? "INVALID": "",
                    ptr_loc, ptr_loc+offset, offset);

            if (ptr_info->invalid) {
                update_residual_loc(ptr_loc, ptr_loc+offset);
                continue;
            }

            assert (ptr_info->dst_info);
            LOCK(ptr_info->dst_info->in_mutex);
            erase_it(ptr_info->dst_info->in_edges, (ptr_info->dst_it));

            auto dst_it = push_back_it(ptr_info->dst_info->in_edges, (ptr_loc+offset));
            //PRINTF(0, "dst_it %016lx, val %016lx\n", dst_it, ptr_loc+offset);
            UNLOCK(ptr_info->dst_info->in_mutex);


            /* Update outedges */
            auto src_it = push_back_it(new_info->out_edges, (ptr_loc+offset));
            //PRINTF(0, "src_it %016lx, val %016lx\n", src_it, ptr_loc+offset);

            /* Update ptr_record */
            struct pointer_info_t *new_ptr_info = (struct pointer_info_t*)__malloc(sizeof(struct pointer_info_t));
            *new_ptr_info = *ptr_info;
            new_ptr_info->loc = ptr_loc + offset;
            new_ptr_info->src_obj += offset;
            new_ptr_info->src_info = new_info;
            new_ptr_info->src_it = src_it;
            new_ptr_info->dst_it = dst_it;
            //__free(ptr_info);
            ptr_record->insert(ptr_loc, nullptr);
            ptr_record->insert(ptr_loc+offset, new_ptr_info);

        }
        old_info->out_edges.clear();

    }
    if (oldptr)
        dealloc_hook_(oldptr, sig, invalidate_mode > 2);

    
    
}

/*
 * This function returns the address of the memory object
 * this ptr_val points to as long as it's with the range
 */
bool get_object_addr(uintptr_t addr, uintptr_t &object_addr, struct object_info_t* &object_info) {

    auto obj = memory_objects->find(addr);

    if (obj) {
        object_addr = obj->addr;
        object_info = obj;
        return 1;
    }

    return 0;
}

inline void deregptr_dst(struct pointer_info_t *ptr_info) {

    /* Remove ptr from dst_obj's in_edges if ptr isn't invalidated */
    if (!ptr_info->invalid) {
        assert(ptr_info->dst_info && "dst_obj in_edges not cleared");
        LOCK(ptr_info->dst_info->in_mutex);
        erase_it(ptr_info->dst_info->in_edges, (ptr_info->dst_it));
        UNLOCK(ptr_info->dst_info->in_mutex);
    } 
}

inline void deregptr_src(struct pointer_info_t *ptr_info) {

    /* Remove ptr from src_obj's out_edges */
    assert( ptr_info->src_info && "src_obj out_edges not cleared");
    erase_it(ptr_info->src_info->out_edges, (ptr_info->src_it));
}

bool deregptr_(uintptr_t ptr_loc) {

    
    pointer_info_t *ptr_info = ptr_record->find(ptr_loc);
    if (ptr_info && ptr_info->loc == ptr_loc) {

        deregptr_dst(ptr_info);
        deregptr_src(ptr_info);

        if (ptr_info->invalid) {
            remove_from_residuals(ptr_loc);
        }

        ptr_record->insert(ptr_loc, nullptr);
        
        return 0;
    }
    
    return 0;

}

EXT_C void regptr(char* ptr_loc_, char* ptr_val_, uint32_t id) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;
    uintptr_t ptr_val= (uintptr_t)ptr_val_;
    
    uintptr_t obj_addr, ptr_obj_addr;
    struct object_info_t *obj_info, *ptr_obj_info;
    obj_addr = ptr_obj_addr = 0;
    obj_info = ptr_obj_info = NULL;
/*    
    if (*(uintptr_t*)ptr_loc == ptr_val ) {
        return;
    }
*/
    
    deregptr_(ptr_loc);

    if (ptr_val < 4096) {
        
        return;
    }

    get_object_addr(ptr_val, obj_addr, obj_info);
    get_object_addr(ptr_loc, ptr_obj_addr, ptr_obj_info);
    PRINTF(3, "[HeapExpo][regptr]: loc:%016lx val:%016lx id:%08x\n[HeapExpo][regptr]: %016lx -> %016lx\n", ptr_loc, ptr_val, id, ptr_obj_addr, obj_addr);

    check_residuals();
    
    /* Create an edge if src and dst are both in memory_objects*/
    if (obj_addr && ptr_obj_addr && obj_addr != ptr_obj_addr) {
        LOCK(obj_info->in_mutex);
        auto dst_it = push_back_it(obj_info->in_edges, (ptr_loc));
        //PRINTF(0, "dst_it %016lx, val %016lx\n", dst_it, ptr_loc);
        UNLOCK(obj_info->in_mutex);
        auto src_it = push_back_it(ptr_obj_info->out_edges, (ptr_loc));
        //PRINTF(0, "src_it %016lx, val %016lx\n", src_it, ptr_loc);
        pointer_info_t pit = pointer_info_t(ptr_loc, ptr_val, ptr_obj_addr, obj_addr,
                                ptr_obj_info, obj_info, src_it, dst_it, id);
        struct pointer_info_t *new_ptr_info = (struct pointer_info_t*)__malloc(sizeof(pointer_info_t));
        *new_ptr_info = pit;
        
        ptr_record->insert(ptr_loc, new_ptr_info);
        
    }

    /* 
     * Only the object in recorded heap
     * Ptr may locate on the stack
     */
    if (obj_addr && !ptr_obj_addr ) {
        if (!stack_record) {
            INT_MALLOC(stack_record, sptype);
        }
        stack_record->insert(stack_pointer_t(ptr_loc, ptr_val, obj_info, id));
    }

    
}

EXT_C void stack_regptr(char* ptr_loc_, char* ptr_val_, uint32_t id) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;
    uintptr_t ptr_val= (uintptr_t)ptr_val_;
    
    uintptr_t obj_addr;
    struct object_info_t *obj_info;
    obj_addr = 0;
    obj_info = NULL;
    
    if (ptr_val < 4096) {
        return;
    }

    get_object_addr(ptr_val, obj_addr, obj_info);
    PRINTF(3, "[HeapExpo][stack_regptr]: loc:%016lx val:%016lx id:%08x obj:%016lx\n", ptr_loc, ptr_val, id, obj_addr);

    if (obj_addr && obj_info && obj_info->addr == obj_addr) {
        if (!stack_record) {
            INT_MALLOC(stack_record, sptype);
        }
        stack_record->insert(stack_pointer_t(ptr_loc, ptr_val, obj_info, id));
    }

}


EXT_C void deregptr(char* ptr_loc_, uint32_t id) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;

    PRINTF(3, "[HeapExpo][deregptr]: loc:%016lx id:%08x\n", ptr_loc, id);
    check_residuals();
    
    deregptr_(ptr_loc);
    

}

EXT_C void initcallstack() {

}

EXT_C void voidcallstack() {

    uintptr_t sp;

#ifdef __x86_64__
    asm("\t movq %%rsp,%0" : "=r"(sp));
#else
    asm("\t movl %%esp,%0" : "=r"(sp));
#endif

    if (stack_record)  {
        stack_record->erase_lower(stack_pointer_t(sp + 0x10));
    }

}

EXT_C void checkstackvar(char* ptr_loc_, uint32_t id) {

    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;
    uintptr_t cur_val = *(uintptr_t*)ptr_loc;


    /*
    if (id == 0x7155daf7) {
        PRINTF(0, "DEBUG %p\n", ptr);
        stack_record->check();
    }
    if (ptr && ptr->dst_info->addr <= cur_val && cur_val < ptr->dst_info->addr + ptr->dst_info->size
            && ptr->dst_info->released) {
            */
    if (is_invalid(cur_val)) {
        stack_pointer_t *ptr = stack_record->find(stack_pointer_t(ptr_loc));
        /*
        PRINTF(3, "[HeapExpo][checkstackvar] PTR[%016lx], %d %d %d %d\n", ptr_loc,
                ptr, ptr->dst_info->addr <= cur_val, cur_val < ptr->dst_info->addr +
                ptr->dst_info->size, ptr->dst_info->released);
                */
        if (ptr && (ptr->dst_info->addr | KADDR) <= cur_val && cur_val < (ptr->dst_info->addr + ptr->dst_info->size | KADDR)
                && ptr->dst_info->released) {
            uint32_t store_id = ptr->store_id;
            PRINTF(2, "[HeapExpo][live_invalid_stack] PTR[%016lx] id:[%08lx] store_id[%08lx] val[%016lx]\n", 
                    ptr_loc, id, store_id, cur_val);
            if (invalidate_mode > 1)
                *(uintptr_t*)ptr_loc = cur_val | KADDR; 

        }

    }
    
}

EXT_C void memcpy_hook(char* dst_, char*src_, size_t num) {

    if (!memory_objects)
        return;

    uintptr_t src = (uintptr_t) src_;
    uintptr_t dst = (uintptr_t) dst_;

    auto src_obj = memory_objects->find(src);
    auto dst_obj = memory_objects->find(dst);

    
    if (src_obj && dst_obj && src_obj->addr == src && dst_obj->addr == dst) {
        PRINTF(2, "[HeapExpo][memcpy] [%016lx:%08lx] -> [%016lx]\n", 
                (uintptr_t)src, num, (uintptr_t)dst);

        src_obj->copied = true;
    }
}

