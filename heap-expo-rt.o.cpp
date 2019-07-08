#define AFL
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

#ifdef AFL
#include "afl-include.h"
#endif
#include "rt-include.h"
#include "malloc-rt.h"


/*
 * LVL0: Production
 * LVL1: Debug version, need to set env HEAP_EXPO_DEBUG
 * LVL2: Debug version
 */
#define DEBUG_LVL 0
#if DEBUG_LVL >= 1
#define PRINTF(...) __printf(__VA_ARGS__)
#else
#define PRINTF(...) 
#endif

using namespace std;

#ifdef MULTITHREADING
#include <pthread.h>
#define LOCK(mtx) mtx.lock()
#define UNLOCK(mtx) mtx.unlock()
#define SLOCK(mtx) mtx.lock_shared()
#define SUNLOCK(mtx) mtx.unlock_shared()
#else
#define LOCK(mtx)
#define UNLOCK(mtx)
#define SLOCK(mtx)
#define SUNLOCK(mtx)
#endif

#ifdef AFL
#include <fstream>
#include <sys/shm.h>
char  __heap_expo_initial[HE_MAP_SIZE];
char* __heap_expo_ptr = __heap_expo_initial;
#endif 


he_map<uintptr_t, struct object_info_t> *memory_objects;
shared_mutex obj_mutex;
he_unordered_map<uintptr_t, struct pointer_info_t> *ptr_record; // Log all all ptrs and the object addr 
shared_mutex ptr_mutex;

bool he_initialized = false;


#if DEBUG_LVL == 1
int debug_mode = 0; 
#endif

#if DEBUG_LVL >= 1
void __printf(const char * format, ...) {
#if DEBUG_LVL == 1
    if (!debug_mode) 
        debug_mode = getenv("HEAP_EXPO_DEBUG") ? 1 : 2;

    if (debug_mode == 2) return;
#endif

    int n1, n2, n3;
    char str[256] = {0};
    va_list args;
    n1 = snprintf(str, 19, "[%016lx]", pthread_self());
    va_start(args, format);
    n2 = vsnprintf(str+n1, 256, format, args);
    va_end(args);
    if (!(n3 = write(2, str, n1+n2))) 
        abort();
}
#endif

EXT_C void msg(const char* str) {
#if DEBUG_LVL >=1
    __printf(str);
#endif
}
void print_memory_objects() {
    SLOCK(obj_mutex);
    PRINTF("Objects List:\n");
    for (auto it = memory_objects->begin(); it != memory_objects->end(); it++) {
        PRINTF("%s Object: %016lx:%016lx\n", getTypeString(it->second.type), it->first, it->second.size);
    }
    SUNLOCK(obj_mutex);
}

void print_edges() {
    PRINTF("Edges List:\n");
    SLOCK(obj_mutex);
    SLOCK(ptr_mutex);
    for (auto it = memory_objects->begin(); it != memory_objects->end(); it++) {
        for (uintptr_t ptr_loc: it->second.out_edges) {
            assert(ptr_record->find(ptr_loc) != ptr_record->end() && "ptr_record does not have this ptr");
            PRINTF("Heap Edge: %016lx->%016lx\n", it->first, ptr_record->at(ptr_loc).dst_obj);
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

#ifdef AFL
inline void print_map() {
#if DEBUG_LVL >1
    ofstream fout;
    PRINTF("Map printing\n");
    fout.open("map", ios::binary|ios::out);

    fout.write(__heap_expo_ptr, HE_MAP_SIZE);
    fout.close();
    PRINTF("Map printed\n");
#endif
}

void print_remaining() {
    he_unordered_set<int32_t> labels;
    uint32_t sig;
    uint16_t offset;
    for (auto moit = memory_objects->begin(); moit != memory_objects->end(); moit++) {
        sig = moit->second.signature;
        for (uintptr_t p: moit->second.in_edges) {
            labels.insert(ptr_record->at(p).id);
        }
        offset = hash<uint32_t>()(sig) & 0xfff + 0x1000;
        PRINTF("[HeapExpo][bitmap]: offset:%04lx, n:%d\n", offset, labels.size());
        __heap_expo_ptr[offset] |= (1 << labels.size());
        
        labels.clear();
    }
}

void __heap_expo_shm() {

    char *id_str = getenv(HE_SHM_ENV_VAR);

    if (id_str) {
        uint32_t shm_id = atoi(id_str);

        __heap_expo_ptr = (char*)shmat(shm_id, NULL, 0);

        if (__heap_expo_ptr == (void*)-1) exit(1);

    }
    
    memset(__heap_expo_ptr, 0x0, HE_MAP_SIZE);
    __heap_expo_ptr[0] = 1;
}
#endif

EXT_C void global_hook(char* addr, size_t size) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)addr;
    PRINTF("[HeapExpo][global]: ptr:%016lx size:%016lx\n", ptr, size);
    LOCK(obj_mutex);
    memory_objects->insert(make_pair<>(ptr, object_info_t(size, GLOBAL)));
    UNLOCK(obj_mutex);
}

void __attribute__((constructor (101))) init_rt(void) {
    memory_objects = (he_map<uintptr_t, struct object_info_t>*)__malloc(sizeof(he_map<uintptr_t, struct object_info_t>));
    new(memory_objects) he_map<uintptr_t, struct object_info_t>;
    ptr_record = (he_unordered_map<uintptr_t, struct pointer_info_t>*)__malloc(sizeof(he_unordered_map<uintptr_t, struct pointer_info_t>));
    new(ptr_record) he_unordered_map<uintptr_t, struct pointer_info_t>;
    ptr_record->reserve(1024);
    PRINTF("STL objects initialized\n");

#ifdef AFL
    __heap_expo_shm();
#endif

    he_initialized = true;
}

void __attribute__((destructor (65535))) fini_rt(void) {
    print_heap();
#ifdef AFL
    print_map();
    print_remaining();
#endif
    //__free(ptr_record);
    //__free(memory_objects);
}

inline uint32_t get_signature() {
    int cnt = -1;
    int size = 4;
    //void *array[4] = {0};
    uint32_t sig = 0;
    unw_cursor_t cursor;
    unw_context_t uc;
    unw_word_t ip;
    unw_getcontext(&uc);
    unw_init_local(&cursor, &uc);
    while (unw_step(&cursor) > 0 && cnt < size) {
        unw_get_reg(&cursor, UNW_REG_IP, &ip);
        if (++cnt >= 0) {
            //array[cnt] = (void*)ip;
            sig ^= ((uintptr_t)ip & 0xffff) << (cnt%4)*16;
        }
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
    PRINTF("[HeapExpo][alloc]: ptr:%016lx size:%016lx\n", ptr, size);
    if (ptr) {
        uint32_t sig = get_signature();
        LOCK(obj_mutex);
        alloc_hook_(ptr, size, sig);
        UNLOCK(obj_mutex);
    }
}

inline void dealloc_hook_(uintptr_t ptr, bool invalidate) {

    auto moit = memory_objects->find(ptr);


    /* Not very likely but ptr may be allocated by other libraries */
    if (moit == memory_objects->end()) {
        return;
    }
#ifdef AFL
    uint32_t sig = moit->second.signature;
    he_unordered_set<uintptr_t> labels = {};
#endif

    PRINTF("[HeapExpo][dealloc_sig]: Object %016lx:%016lx is allocated with signature %08lx\n", moit->first, moit->second.size, moit->second.signature);
    
    /* Invalidate ptrs that point to this heap object */
    SLOCK(moit->second.in_mutex);
    for (uintptr_t ptr_loc: moit->second.in_edges) {
        auto it = ptr_record->find(ptr_loc);
        if (it == ptr_record->end()) {
            PRINTF("Cannot Find PTR[%016lx] in ptr_record\n", ptr_loc);
            assert(false && "cannot find ptr in ptr_record");
            continue;
        }

        assert(ptr == it->second.dst_obj);
        
        uintptr_t cur_val = *(uintptr_t*)ptr_loc;

        /* Value did not change, set it to kernel space */
        if (cur_val != it->second.value) {
            uintptr_t src_obj_addr = it->second.src_obj;
            struct object_info_t *src_obj_info = it->second.src_info;
            if (cur_val < src_obj_addr || cur_val >= src_obj_addr + src_obj_info->size) {
                PRINTF("PTR[%016lx] has unknown behavior\n", ptr_loc);
                PRINTF("Record: value: %016lx src_obj:%016lx dst_obj:%016lx\n",
                        it->second.value, it->second.src_obj, it->second.dst_obj);
                PRINTF("Current value: %016lx\n", cur_val);
                if (!src_obj_info->out_edges.erase(ptr_loc)) 
                    assert(false &&"smoit incongruence");
                ptr_record->erase(it);

                continue;
            }

        }
        if (invalidate)
#if __x86_64__
            *(uintptr_t*)ptr_loc = cur_val | 0xffff800000000000; 
#else
            *(uintptr_t*)ptr_loc = cur_val | 0xc0000000;
#endif
        PRINTF("[HeapExpo][invalidate]: ptr_loc:%016lx value:%016lx\n", ptr_loc, it->second.value);

#ifdef AFL
        labels.insert(it->second.id);
#endif

        it->second.invalid = true;
    }
    SUNLOCK(moit->second.in_mutex);
    LOCK(moit->second.in_mutex);
    moit->second.in_edges.clear();
    UNLOCK(moit->second.in_mutex);

    /* Erase ptrs in this heap object */
    for (uintptr_t ptr_loc: moit->second.out_edges) {
        auto it = ptr_record->find(ptr_loc);
        PRINTF("[HeapExpo][remove]: ptr_loc:%016lx obj:%016lx\n", ptr_loc, moit->first);
        assert(it != ptr_record->end());
        if (!it->second.invalid) {
            struct object_info_t *dst_obj_info = it->second.dst_info;
            LOCK(dst_obj_info->in_mutex);
            if (!dst_obj_info->in_edges.erase(ptr_loc)) {
                assert(false && "Cannot remove ptr_loc");
            }
            UNLOCK(dst_obj_info->in_mutex);
        }
        ptr_record->erase(it);
    }


    moit->second.out_edges.clear();

    memory_objects->erase(moit);
   
#ifdef AFL
    uint16_t offset = hash<uint32_t>()(sig) & 0xfff;
    PRINTF("[HeapExpo][bitmap]: offset:%04lx, n:%d\n", offset, labels.size());
    __heap_expo_ptr[offset] |= (1 << labels.size());
#endif
}

/* XXX: unwind stack */
EXT_C void dealloc_hook(char* ptr_) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)ptr_;
    PRINTF("[HeapExpo][dealloc]: ptr:%016lx\n", ptr);
    if (ptr) {
        LOCK(obj_mutex);
        LOCK(ptr_mutex);
        dealloc_hook_(ptr, true);
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
    bool inval_in_ptrs = true;
    if (!he_initialized) return;
    uintptr_t oldptr = (uintptr_t)oldptr_;
    uintptr_t newptr = (uintptr_t)newptr_;
    int offset = newptr - oldptr;
    uint32_t sig = get_signature();
    PRINTF("[HeapExpo][realloc]: oldptr:%016lx newptr:%016lx size:%016lx\n", oldptr, newptr, newsize);
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
            uintptr_t cur_val = *(uintptr_t*)(ptr_loc+offset);
            /* If value changed, we don't move this ptr */
            if (cur_val != it->second.value) {
                PRINTF("PTR[%016lx] value has changed\n", ptr_loc);
                ptr_record->erase(it);
                continue;
            }

            PRINTF("MOVING PTR[%016lx] to %016lx, OFFSET:%016lx\n", ptr_loc, ptr_loc+offset, offset);
            assert (it->second.dst_info);
            assert (memory_objects->find(it->second.dst_obj) != memory_objects->end());
            assert (it->second.dst_info == &memory_objects->at(it->second.dst_obj));
            LOCK(it->second.dst_info->in_mutex);
            if (! it->second.dst_info->in_edges.erase(ptr_loc))
                assert(false && "in edge problem");

            it->second.dst_info->in_edges.insert(ptr_loc+offset);
            UNLOCK(it->second.dst_info->in_mutex);

            /* Update outedges */
            memory_objects->at(newptr).out_edges.insert(ptr_loc+offset);

            /* Update ptr_record */
            assert(it != ptr_record->end());
            ptr_record->insert(make_pair<>(ptr_loc+offset, it->second));
            ptr_record->erase(it);
            ptr_record->at(ptr_loc+offset).src_obj += offset;
            ptr_record->at(ptr_loc+offset).src_info = &memory_objects->at(newptr);

        }
        memory_objects->at(oldptr).out_edges.clear();
        if (memory_objects->at(oldptr).in_edges.size() == 1)
            inval_in_ptrs = false;
    }
    if (oldptr)
        dealloc_hook_(oldptr, inval_in_ptrs);

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
            PRINTF("dst_obj: loc:%016lx\n", it->second.dst_obj);
            assert (false && "deregptr in edge problem");
        }
        UNLOCK(it->second.dst_info->in_mutex);
    } 
}

inline void deregptr_src(he_unordered_map<uintptr_t, struct pointer_info_t>::iterator it) {

    /* Remove ptr from src_obj's out_edges */
    assert( it->second.src_info && "src_obj out_edges not cleared");
    if (! it->second.src_info->out_edges.erase(it->first)) {
        PRINTF("src_obj: loc:%016lx\n", it->second.src_obj);
        assert (false && "deregptr out edge problem");
    }
}

inline bool deregptr_(uintptr_t ptr_loc, bool keep) {

    SLOCK(ptr_mutex);
    auto it = ptr_record->find(ptr_loc);
    if (it != ptr_record->end()) {
        deregptr_dst(it);
        deregptr_src(it);
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
    PRINTF("[HeapExpo][regptr]: loc:%016lx val:%016lx\n[HeapExpo][regptr]: %016lx -> %016lx\n", ptr_loc, ptr_val, ptr_obj_addr, obj_addr);
    
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

    PRINTF("[HeapExpo][deregptr]: loc:%016lx\n", ptr_loc);
    SLOCK(obj_mutex);
    deregptr_(ptr_loc, false);
    SUNLOCK(obj_mutex);

}

#undef PRINTF
