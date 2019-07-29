#include <cstdio>
#include <utility>
#include <map>
#include <set>
#include <unordered_map>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>

#define UNW_LOCAL_ONLY
#if __x86_64__
#include <libunwind.h>
#else
#include <libunwind-x86.h>
#endif

#define AFL
#ifdef AFL
#include "afl-include.h"
#endif

#include "rt-include.h"
#include "rt-malloc.h"
#include "hash.h"
#include <execinfo.h>

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

#ifdef AFL
#include <fstream>
#include <sys/shm.h>
ESP_ST char  __heap_expo_initial[HE_MAP_SIZE];
ESP_ST char* __heap_expo_ptr = __heap_expo_initial;
#endif 


using motype = he_map<uintptr_t, struct object_info_t>;
ESP_ST motype *memory_objects;

using prtype = he_unordered_map<uintptr_t, struct pointer_info_t>;
ESP_ST prtype *ptr_record; // Log all all ptrs and the object addr 

using rtype = he_list<residual_pointer_t>;
ESP_ST thread_local rtype *residuals = NULL;
ESP_ST thread_local int64_t counter = 0;
ESP_ST int64_t residual_live_limit = 1000;

using s2dtype = he_unordered_set<uint32_t>;
ESP_ST s2dtype *sig2dbg;

#ifdef MULTITHREADING
ESP_ST shared_mutex obj_mutex;
ESP_ST shared_mutex ptr_mutex;
ESP_ST shared_mutex sig_mutex;
#endif

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
void __printf(int lvl, const char * format, ...) {
#if DEBUG_LVL == 1
    if (print_mode < lvl) return;
#endif

    /* Make a copy in case stderr got closed */
    int n1, n2, n3;
    char str[256] = {0};
    va_list args;
    n1 = 0;//snprintf(str, 19, "[%016lx]", pthread_self());
    va_start(args, format);
    n2 = vsnprintf(str+n1, 256, format, args);
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
void print_memory_objects() {
    SLOCK(obj_mutex);
    PRINTF(3, "Objects List:\n");
    for (auto it = memory_objects->begin(); it != memory_objects->end(); it++) {
        PRINTF(3, "%s Object: %016lx:%016lx\n", getTypeString(it->second.type), it->first, it->second.size);
    }
    SUNLOCK(obj_mutex);
}

void print_edges() {
    PRINTF(3, "Edges List:\n");
    SLOCK(obj_mutex);
    SLOCK(ptr_mutex);
    for (auto it = memory_objects->begin(); it != memory_objects->end(); it++) {
        for (uintptr_t ptr_loc: it->second.out_edges) {
            assert(ptr_record->find(ptr_loc) != ptr_record->end() && "ptr_record does not have this ptr");
            PRINTF(3, "Heap Edge: %016lx->%016lx\n", it->first, ptr_record->at(ptr_loc).dst_obj);
        }
    }
    SUNLOCK(ptr_mutex);
    SUNLOCK(obj_mutex);
}

EXT_C void print_heap() {
#if DEBUG_LVL > 1
    print_memory_objects();
    print_edges();
#endif
}

        

void __heap_expo_shm() {

    char *id_str = getenv(HE_SHM_ENV_VAR);

    if (id_str) {
        uint32_t shm_id = atoi(id_str);

        __heap_expo_ptr = (char*)shmat(shm_id, NULL, 0);

        if (__heap_expo_ptr == (void*)-1) exit(1);

        __heap_expo_ptr[0] = 1;

    }
    
}


bool get_object_addr(uintptr_t, uintptr_t&, struct object_info_t *&);
EXT_C void global_hook(char* addr, size_t size) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)addr;
    PRINTF(3, "[HeapExpo][global]: ptr:%016lx size:%016lx\n", ptr, size);
    LOCK(obj_mutex);
    memory_objects->insert(make_pair<>(ptr, object_info_t(size, GLOBAL)));
    UNLOCK(obj_mutex);
}

inline void init_global_vars() {

    INT_MALLOC(memory_objects, motype); 

    INT_MALLOC(ptr_record, prtype);
    ptr_record->reserve(1024);

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

#ifdef AFL
    __heap_expo_shm();
#endif

    he_initialized = true;
}

void __attribute__((destructor (65535))) fini_rt(void) {

    print_heap();

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
    if (status) exit(status);

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

inline void check_double_free(uintptr_t val) {
    bool invalid;
#ifdef __x86_64__
    invalid = !!(val & 0xffff800000000000);
#else 
    invalid = !!(val & 0xc0000000);
#endif

    if (invalid) {
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

inline uint32_t get_signature() {
    /* ignore this func, hook, and malloc/free */
    int cnt = -3;
    int size = 8;
    void *array[8] = {0};
    uint32_t sig = 0;
    unw_cursor_t cursor;
    unw_context_t uc;
    unw_word_t ip;
    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);
    while (unw_step(&cursor) > 0 && cnt < size) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        if (++cnt >= 0) {
            array[cnt] = (void*)ip;
            //sig ^= ((uintptr_t)ip & 0xffff) << (cnt%4)*16;
        }
    }
    sig = hash_addr_list((uintptr_t*)array, cnt);
    SLOCK(sig_mutex);
    if (sig2dbg->find(sig) == sig2dbg->end()) {
        PRINTF(2, "SIG[%08x][%d]:\n", sig, cnt);
        if (print_mode >= 2)
            backtrace_symbols_fd(array, cnt, fdcopy);
        SUNLOCK(sig_mutex);
        LOCK(sig_mutex);
        sig2dbg->insert(sig);
        UNLOCK(sig_mutex);
    } else {
        SUNLOCK(sig_mutex);
    }
    return sig;
}

inline void alloc_hook_(uintptr_t ptr, size_t size, uint32_t sig) {
    /* Add heap object to memory_objects. Simple */
    memory_objects->insert(make_pair<>(ptr, object_info_t(size, HEAP, sig)));
}

/* XXX: unwind stack */
EXT_C void alloc_hook(char* ptr_, size_t size) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)ptr_;
    PRINTF(3, "[HeapExpo][alloc]: ptr:%016lx size:%016lx\n", ptr, size);
    if (ptr) {
        uint32_t sig = get_signature();
        LOCK(obj_mutex);
        alloc_hook_(ptr, size, sig);
        UNLOCK(obj_mutex);
    }
}

inline void dealloc_hook_(uintptr_t ptr, uint32_t free_sig, bool invalidate) {

    auto moit = memory_objects->find(ptr);


    /* Not very likely but ptr may be allocated by other libraries */
    if (moit == memory_objects->end()) {
        return;
    }

    PRINTF(3, "[HeapExpo][dealloc_sig]: Object %016lx:%016lx is allocated with signature %08lx\n", moit->first, moit->second.size, moit->second.signature);

    rtype tmp; 
    /* Invalidate ptrs that point to this heap object */
    SLOCK(moit->second.in_mutex);
    for (uintptr_t ptr_loc: moit->second.in_edges) {
        auto it = ptr_record->find(ptr_loc);
        if (it == ptr_record->end()) {
            PRINTF(3, "Cannot Find PTR[%016lx] in ptr_record\n", ptr_loc);
            assert(false && "cannot find ptr in ptr_record");
            continue;
        }

        assert(ptr == it->second.dst_obj);
        
        uintptr_t cur_val = *(uintptr_t*)ptr_loc;

        if (cur_val != it->second.value) {

            struct object_info_t *src_obj_info = it->second.src_info;

            PRINTF(3, "PTR[%016lx] has unknown behavior\n", ptr_loc);
            PRINTF(3, "Record: value: %016lx src_obj:%016lx dst_obj:%016lx\n",
                    it->second.value, it->second.src_obj, it->second.dst_obj);
            PRINTF(3, "Current value: %016lx\n", cur_val);
            if (!src_obj_info->out_edges.erase(ptr_loc)) 
                assert(false &&"smoit incongruence");
            ptr_record->erase(it);

            continue;

        }
        
        /* Value did not change, set it to kernel space */
        if (invalidate)
#if __x86_64__
            *(uintptr_t*)ptr_loc = cur_val | 0xffff800000000000; 
#else
            *(uintptr_t*)ptr_loc = cur_val | 0xc0000000;
#endif
        PRINTF(3, "[HeapExpo][invalidate]: ptr_loc:%016lx value:%016lx\n", ptr_loc, it->second.value);
        tmp.push_back(residual_pointer_t(ptr_loc, *(uintptr_t*)ptr_loc,
                    it->second.src_info->signature, it->second.dst_info->signature,
                    free_sig, it->second.id, counter));

        it->second.invalid = true;
    }

    for (auto &p: tmp) 
        p.adj_cnt += tmp.size();

    if (!residuals) {
        INT_MALLOC(residuals, rtype);
    }

    residuals->merge(tmp, cntcmp);

    SUNLOCK(moit->second.in_mutex);
    LOCK(moit->second.in_mutex);
    moit->second.in_edges.clear();
    UNLOCK(moit->second.in_mutex);

    /* Erase ptrs in this heap object */
    for (uintptr_t ptr_loc: moit->second.out_edges) {
        auto it = ptr_record->find(ptr_loc);
        PRINTF(3, "[HeapExpo][remove]: ptr_loc:%016lx obj:%016lx\n", ptr_loc, moit->first);
        assert(it != ptr_record->end());
        if (!it->second.invalid) {
            struct object_info_t *dst_obj_info = it->second.dst_info;
            LOCK(dst_obj_info->in_mutex);
            if (!dst_obj_info->in_edges.erase(ptr_loc)) {
                assert(false && "Cannot remove ptr_loc");
            }
            UNLOCK(dst_obj_info->in_mutex);
        }
        else {
            PRINTF(3, "[HeapExpo][remove_invalid]: ptr_loc:%016lx\n", ptr_loc);
            remove_from_residuals(ptr_loc);
        }
            
        ptr_record->erase(it);
    }


    moit->second.out_edges.clear();

    memory_objects->erase(moit);
   
}

/* XXX: unwind stack */
EXT_C void dealloc_hook(char* ptr_) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)ptr_;
    PRINTF(3, "[HeapExpo][dealloc]: ptr:%016lx\n", ptr);
    if (ptr) {
        uint32_t sig = get_signature();
        check_double_free(ptr);
        LOCK(obj_mutex);
        LOCK(ptr_mutex);
        dealloc_hook_(ptr, sig, invalidate_mode>1 );
        UNLOCK(ptr_mutex);
        UNLOCK(obj_mutex);
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
    uint32_t sig = get_signature();
    PRINTF(3, "[HeapExpo][realloc]: oldptr:%016lx newptr:%016lx size:%016lx\n", oldptr, newptr, newsize);
    LOCK(obj_mutex);
    if (offset == 0) {
        memory_objects->at(newptr).size = newsize;
        UNLOCK(obj_mutex);
        return;
    }
    LOCK(ptr_mutex);
    
    if (newptr)
        alloc_hook_(newptr, newsize, sig);

    //size_t oldsize = memory_objects[oldptr].size;

    if (newptr && oldptr) {
        /* Iterate every objects old object points to */
        for (uintptr_t ptr_loc: memory_objects->at(oldptr).out_edges) {



            /* Update inedges */

            auto it = ptr_record->find(ptr_loc);
            assert (it != ptr_record->end()) ;
            
            /* 
             * Shrinked. Ignore ptrs outside range 
             * Must be checked before dereference the addr
             */
            if (ptr_loc >= oldptr + newsize) {
                PRINTF(3, "PTR[%016lx] is discarded while realloc to a smaller area\n", ptr_loc);
                if (!it->second.invalid) {
                    LOCK(it->second.dst_info->in_mutex);
                    it->second.dst_info->in_edges.erase(ptr_loc);
                    UNLOCK(it->second.dst_info->in_mutex);
                }
                else {
                    remove_from_residuals(ptr_loc);
                }
                ptr_record->erase(it);
                continue;
            }

            uintptr_t cur_val = *(uintptr_t*)(ptr_loc+offset);

            /* If value changed, we don't move this ptr */
            if (!it->second.invalid && cur_val != it->second.value) {
                PRINTF(3, "PTR[%016lx] value has changed\n", ptr_loc);
                LOCK(it->second.dst_info->in_mutex);
                it->second.dst_info->in_edges.erase(ptr_loc);
                UNLOCK(it->second.dst_info->in_mutex);
                ptr_record->erase(it);
                continue;
            }


            PRINTF(3, "MOVING %s PTR[%016lx] to %016lx, OFFSET:%016lx\n", 
                    it->second.invalid? "INVALID": "",
                    ptr_loc, ptr_loc+offset, offset);

            if (!it->second.invalid) {

                assert (it->second.dst_info);
                assert (memory_objects->find(it->second.dst_obj) != memory_objects->end());
                assert (it->second.dst_info == &memory_objects->at(it->second.dst_obj));
                LOCK(it->second.dst_info->in_mutex);
                if (! it->second.dst_info->in_edges.erase(ptr_loc))
                    assert(false && "in edge problem");

                it->second.dst_info->in_edges.insert(ptr_loc+offset);
                UNLOCK(it->second.dst_info->in_mutex);

            } else {
                update_residual_loc(ptr_loc, ptr_loc+offset);
            }


            /* Update outedges */
            memory_objects->at(newptr).out_edges.insert(ptr_loc+offset);

            /* Update ptr_record */
            ptr_record->insert(make_pair<>(ptr_loc+offset, it->second));
            ptr_record->at(ptr_loc+offset).src_obj += offset;
            ptr_record->at(ptr_loc+offset).src_info = &memory_objects->at(newptr);
            ptr_record->erase(it);

        }
        memory_objects->at(oldptr).out_edges.clear();

    }
    if (oldptr)
        dealloc_hook_(oldptr, sig, invalidate_mode > 2);

    UNLOCK(ptr_mutex);
    UNLOCK(obj_mutex);
}

/*
 * This function returns the address of the memory object
 * this ptr_val points to as long as it's with the range
 */
bool get_object_addr(uintptr_t addr, uintptr_t &object_addr, struct object_info_t* &object_info) {
    auto it = memory_objects->upper_bound(addr);
    if (it == memory_objects->begin()) {
        return 0;
    }
    it--;
    int diff = addr - it->first;
    if (diff >= 0 && diff < it->second.size) {
        object_addr = it->first;
        object_info = &it->second;
        return 1;
    }
    return 0;
}

inline void deregptr_dst(he_unordered_map<uintptr_t, struct pointer_info_t>::iterator it) {

    /* Remove ptr from dst_obj's in_edges if ptr isn't invalidated */
    if (!it->second.invalid) {
        assert(it->second.dst_info && "dst_obj in_edges not cleared");
        LOCK(it->second.dst_info->in_mutex);
        if (! it->second.dst_info->in_edges.erase(it->first)) {
            PRINTF(3, "dst_obj: loc:%016lx\n", it->second.dst_obj);
            assert (false && "deregptr in edge problem");
        }
        UNLOCK(it->second.dst_info->in_mutex);
    } 
}

inline void deregptr_src(he_unordered_map<uintptr_t, struct pointer_info_t>::iterator it) {

    /* Remove ptr from src_obj's out_edges */
    assert( it->second.src_info && "src_obj out_edges not cleared");
    if (! it->second.src_info->out_edges.erase(it->first)) {
        PRINTF(3, "src_obj: loc:%016lx\n", it->second.src_obj);
        assert (false && "deregptr out edge problem");
    }
}

inline bool deregptr_(uintptr_t ptr_loc, bool keep) {

    SLOCK(ptr_mutex);
    auto it = ptr_record->find(ptr_loc);
    if (it != ptr_record->end()) {

        deregptr_dst(it);
        deregptr_src(it);

        if (it->second.invalid) {
            remove_from_residuals(ptr_loc);
        }

        SUNLOCK(ptr_mutex);
        if (!keep) {
            LOCK(ptr_mutex);
            ptr_record->erase(ptr_loc);
            UNLOCK(ptr_mutex);
            return 0;
        }
        return 1;
    }
    SUNLOCK(ptr_mutex);
    return 0;

}

EXT_C void regptr(char* ptr_loc_, char* ptr_val_, uint32_t id) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;
    uintptr_t ptr_val= (uintptr_t)ptr_val_;
    
    uintptr_t obj_addr, ptr_obj_addr;
    struct object_info_t *obj_info, *ptr_obj_info;
    obj_addr = ptr_obj_addr = 0;
    obj_info = ptr_obj_info = NULL;
    
    if (*(uintptr_t*)ptr_loc == ptr_val ) {
        return;
    }

    SLOCK(obj_mutex);
    bool kept = deregptr_(ptr_loc, true);

    if (ptr_val < 4096) {
        if (kept) {
            LOCK(ptr_mutex);
            ptr_record->erase(ptr_loc);
            UNLOCK(ptr_mutex);
        }
        SUNLOCK(obj_mutex);
        return;
    }

    get_object_addr(ptr_val, obj_addr, obj_info);
    get_object_addr(ptr_loc, ptr_obj_addr, ptr_obj_info);
    PRINTF(3, "[HeapExpo][regptr]: loc:%016lx val:%016lx\n[HeapExpo][regptr]: %016lx -> %016lx\n", ptr_loc, ptr_val, ptr_obj_addr, obj_addr);

    check_residuals();
    
    /* Create an edge if src and dst are both in memory_objects*/
    if (obj_addr && ptr_obj_addr && obj_addr != ptr_obj_addr) {
        LOCK(obj_info->in_mutex);
        obj_info->in_edges.insert(ptr_loc);
        UNLOCK(obj_info->in_mutex);
        ptr_obj_info->out_edges.insert(ptr_loc);
        pointer_info_t pit = pointer_info_t(ptr_val, ptr_obj_addr, obj_addr,
                                            ptr_obj_info, obj_info, id);
        if (!kept) {
            LOCK(ptr_mutex);
            ptr_record->insert(make_pair<>(ptr_loc, pit));
            UNLOCK(ptr_mutex);
        }
        else {
            SLOCK(ptr_mutex);
            ptr_record->at(ptr_loc) = pit;
            SUNLOCK(ptr_mutex);
        }

    }
    else {
        if (kept) {
            LOCK(ptr_mutex);
            ptr_record->erase(ptr_loc);
            UNLOCK(ptr_mutex);
        }
    }
    SUNLOCK(obj_mutex);
}

EXT_C void deregptr(char* ptr_loc_, uint32_t id) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;

    PRINTF(3, "[HeapExpo][deregptr]: loc:%016lx\n", ptr_loc);
    check_residuals();
    SLOCK(obj_mutex);
    deregptr_(ptr_loc, false);
    SUNLOCK(obj_mutex);

}

#undef PRINTF
