#include <cstdio>
#include <utility>
#include <map>
#include <set>
#include <unordered_map>
#include <assert.h>
#include <unistd.h>
#include <stdarg.h>

#include "rt-include.h"


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

using namespace std;

he_map<uintptr_t, struct object_info_t> memory_objects;
he_unordered_map<uintptr_t, struct pointer_info_t> ptr_record; // Log all all ptrs and the object addr 

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

    int n;
    char str[256] = {0};
    va_list args;
    va_start(args, format);
    n = vsnprintf(str, 256, format, args);
    va_end(args);
    if (!(n = write(2, str, n))) 
        abort();
}
#endif

EXT_C void msg(const char* str) {
#if DEBUG_LVL >=1
    __printf(str);
#endif
}

void print_memory_objects() {
    PRINTF("Objects List:\n");
    for (auto it = memory_objects.begin(); it != memory_objects.end(); it++) {
        PRINTF("%s Object: %016lx:%016lx\n", getTypeString(it->second.type), it->first, it->second.size);
    }
}

void print_edges() {
    PRINTF("Edges List:\n");
    for (auto it = memory_objects.begin(); it != memory_objects.end(); it++) {
        for (uintptr_t ptr_loc: it->second.out_edges) {
            assert(ptr_record.find(ptr_loc) != ptr_record.end() && "ptr_record does not have this ptr");
            PRINTF("Heap Edge: %016lx->%016lx\n", it->first, ptr_record[ptr_loc].dst_obj);
        }
    }
}

EXT_C void print_heap() {
    print_memory_objects();
    print_edges();
}

EXT_C void global_hook(char* addr, size_t size) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)addr;
    PRINTF("[HeapExpo][global]: ptr:%016lx size:%016lx\n", ptr, size);
    memory_objects[ptr] = object_info_t(size, GLOBAL);
}

void __attribute__((constructor (-1))) init_rt(void) {
    new(&memory_objects) he_map<uintptr_t, struct object_info_t>;
    new(&ptr_record) he_unordered_map<uintptr_t, struct pointer_info_t>;
    PRINTF("STL objects initialized\n");
    he_initialized = true;
}

inline void alloc_hook_(uintptr_t ptr, size_t size) {
    /* Add heap object to memory_objects. Simple */
    memory_objects[ptr] = object_info_t(size, HEAP);
}

/* XXX: unwind stack */
EXT_C void alloc_hook(char* ptr_, size_t size) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)ptr_;
    PRINTF("[HeapExpo][alloc]: ptr:%016lx size:%016lx\n", ptr, size);
    if (ptr && size)
        alloc_hook_(ptr, size);
}

inline void dealloc_hook_(uintptr_t ptr) {
    if (ptr == 0)
        return;
    auto moit = memory_objects.find(ptr);
    if (moit == memory_objects.end()) 
        return;
    

    /* Invalidate ptrs that point to this heap object */
    for (uintptr_t ptr_loc: moit->second.in_edges) {
        auto it = ptr_record.find(ptr_loc);
        if (it == ptr_record.end()) {
            PRINTF("Cannot Find PTR[%016lx] in ptr_record\n", ptr_loc);
            assert(false && "cannot find ptr in ptr_record");
        }

        assert(ptr == it->second.dst_obj);
        /* A special case */
        /*
        if (it->second.src_obj == it->second.dst_obj) {
            moit->second.out_edges.erase(ptr_loc);
            ptr_record.erase(it);
            continue;
        }*/
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
                ptr_record.erase(it);
                continue;
            }
        }
#if __x86_64__
        *(uintptr_t*)ptr_loc = cur_val | 0xffff800000000000; 
#else
        *(uintptr_t*)ptr_loc = cur_val | 0xc0000000;
#endif
        PRINTF("[HeapExpo][invalidate]: ptr_loc:%016lx value:%016lx\n", ptr_loc, it->second.value);
        it->second.invalid = true;
    }
    moit->second.in_edges.clear();

    /* Erase ptrs in this heap object */
    for (uintptr_t ptr_loc: moit->second.out_edges) {
        auto it = ptr_record.find(ptr_loc);
        PRINTF("[HeapExpo][remove]: ptr_loc:%016lx obj:%016lx\n", ptr_loc, moit->first);
        assert(it != ptr_record.end());
        if (!it->second.invalid) {
            struct object_info_t *dst_obj_info = it->second.dst_info;
            if (!dst_obj_info->in_edges.erase(ptr_loc)) {
                assert(false && "Cannot remove ptr_loc");
            }
        }
        ptr_record.erase(it);
    }
    moit->second.out_edges.clear();

    memory_objects.erase(moit);
}

/* XXX: unwind stack */
EXT_C void dealloc_hook(char* ptr_) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)ptr_;
    PRINTF("[HeapExpo][dealloc]: ptr:%016lx\n", ptr);
    if (ptr)
        dealloc_hook_(ptr);
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
    int offset = newptr - oldptr;
    PRINTF("[HeapExpo][realloc]: oldptr:%016lx newptr:%016lx size:%016lx\n", oldptr, newptr, newsize);
    if (offset == 0) {
        memory_objects[newptr].size = newsize;
        return;
    }
    
    if (newptr && newsize)
        alloc_hook_(newptr, newsize);

    //size_t oldsize = memory_objects[oldptr].size;

    if (newptr && newsize && oldptr) {
        /* Iterate every objects old object points to */
        for (uintptr_t ptr_loc: memory_objects[oldptr].out_edges) {

            /* Update outedges */
            memory_objects[newptr].out_edges.insert(ptr_loc+offset);

            /* Update inedges */
            auto it = ptr_record.find(ptr_loc);
            if (it == ptr_record.end()) 
                continue;
            assert (it->second.dst_info);
            if (! it->second.dst_info->in_edges.erase(ptr_loc))
                assert(false && "in edge problem");

            PRINTF("MOVING PTR[%016lx] to %016lx, OFFSET:%016lx\n", ptr_loc, ptr_loc+offset, offset);
            it->second.dst_info->in_edges.insert(ptr_loc+offset);

            /* Update ptr_record */
            assert(it != ptr_record.end());
            swap(ptr_record[ptr_loc+offset], it->second);
            ptr_record[ptr_loc+offset].src_obj += offset;
            ptr_record[ptr_loc+offset].src_info = &memory_objects[newptr];
            ptr_record.erase(it);

        }
        memory_objects[oldptr].out_edges.clear();
    }
    if (oldptr)
        dealloc_hook_(oldptr);
}

/*
 * This function returns the address of the memory object
 * this ptr_val points to as long as it's with the range
 */
bool get_object_addr(uintptr_t addr, uintptr_t &object_addr, struct object_info_t* &object_info) {
    auto it = memory_objects.upper_bound(addr);
    if (it == memory_objects.begin()) {
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

inline void deregptr_(uintptr_t ptr_loc) {
    auto it = ptr_record.find(ptr_loc);
    if (it == ptr_record.end())
        return;

    /* Remove ptr from dst_obj's in_edges if ptr isn't invalidated */
    if (!it->second.invalid) {
        assert(it->second.dst_info && "dst_obj in_edges not cleared");
        if (! it->second.dst_info->in_edges.erase(ptr_loc)) {
            PRINTF("dst_obj: loc:%016lx\n", it->second.dst_obj);
            assert (false && "deregptr in edge problem");
        }
    }

    /* Remove ptr from src_obj's out_edges */
    assert( it->second.src_info && "src_obj out_edges not cleared");
    if (! it->second.src_info->out_edges.erase(ptr_loc)) {
        PRINTF("src_obj: loc:%016lx\n", it->second.src_obj);
        assert (false && "deregptr out edge problem");
    }
    /* Remove ptr from ptr_record */
    ptr_record.erase(it);
}

EXT_C void regptr(char* ptr_loc_, char* ptr_val_) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;
    uintptr_t ptr_val= (uintptr_t)ptr_val_;
    
    PRINTF("[HeapExpo][regptr]: loc:%016lx val:%016lx\n", ptr_loc, ptr_val);

    uintptr_t obj_addr, ptr_obj_addr;
    struct object_info_t *obj_info, *ptr_obj_info;
    obj_addr = ptr_obj_addr = 0;
    obj_info = ptr_obj_info = NULL;
    get_object_addr(ptr_val, obj_addr, obj_info);
    get_object_addr(ptr_loc, ptr_obj_addr, ptr_obj_info);
    PRINTF("[HeapExpo][regptr]: %016lx -> %016lx\n", ptr_obj_addr, obj_addr);
    
    /* Overwrite old ptr if exists */
    deregptr_(ptr_loc);

    /* Create an edge if src and dst are both in memory_objects*/
    if (obj_addr && ptr_obj_addr && obj_addr != ptr_obj_addr) {
        obj_info->in_edges.insert(ptr_loc);
        ptr_obj_info->out_edges.insert(ptr_loc);
        ptr_record[ptr_loc] = pointer_info_t(ptr_val, ptr_obj_addr, obj_addr,
                                                ptr_obj_info, obj_info);
    }
}

EXT_C void deregptr(char* ptr_loc_) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;

    PRINTF("[HeapExpo][deregptr]: loc:%016lx\n", ptr_loc);
    deregptr_(ptr_loc);

}

#undef PRINTF
