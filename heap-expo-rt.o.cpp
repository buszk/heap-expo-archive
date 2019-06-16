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

/* XXX: object type */
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
    if (!(n = write(1, str, n))) 
        abort();
}
#endif


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

/* 
 * XXX: Destructor not working because of freeing of heap memory 
 */
/*
void __attribute__((destructor(1000000))) fini_rt(void) 
    print_memory_objects();
    print_edges();
}
*/

inline void alloc_hook_(uintptr_t ptr, size_t size) {
    memory_objects[ptr] = object_info_t(size, HEAP);
}
/* XXX: unwind stack */
EXT_C void alloc_hook(char* ptr_, size_t size) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)ptr_;
    PRINTF("[HeapExpo][alloc]: ptr:%016lx size:%016lx\n", ptr, size);
    alloc_hook_(ptr, size);
}

inline void dealloc_hook_(uintptr_t ptr) {
    auto it = memory_objects.find(ptr);
    if (it == memory_objects.end()) 
        return;
    
    memory_objects.erase(it);
}

/* XXX: unwind stack */
EXT_C void dealloc_hook(char* ptr_) {
    if (!he_initialized) return;
    uintptr_t ptr = (uintptr_t)ptr_;
    PRINTF("[HeapExpo][dealloc]: ptr:%016lx\n", ptr);
    dealloc_hook_(ptr);
}

/* XXX: unwind stack */
EXT_C void realloc_hook(char* oldptr_, char* newptr_, size_t newsize) {
    if (!he_initialized) return;
    uintptr_t oldptr = (uintptr_t)oldptr_;
    uintptr_t newptr = (uintptr_t)newptr_;
    int offset = newptr - oldptr;
    PRINTF("[HeapExpo][realloc]: oldptr:%016lx newptr:%016lx size:%016lx\n", oldptr, newptr, newsize);
    if (offset == 0) {
        memory_objects[newptr].size = newsize;
        return;
    }
    size_t oldsize = memory_objects[oldptr].size;
    alloc_hook_(newptr, newsize);

    /* Iterate every objects old object points to */
    for (uintptr_t ptr_loc: memory_objects[oldptr].out_edges) {

        /* Update outedges */
        memory_objects[newptr].out_edges.insert(ptr_loc+offset);

        /* Update inedges */
        auto it = ptr_record.find(ptr_loc);
        if (it == ptr_record.end()) 
            continue;
        auto moit = memory_objects.find(it->second.dst_obj);
        if (moit== memory_objects.end())
            continue;
        if (moit->second.in_edges.count(ptr_loc))
            moit->second.in_edges.erase(ptr_loc);
        else 
            assert(false && "in edge problem");
        moit->second.in_edges.insert(ptr_loc+offset);

        /* Update ptr_record */
        assert(it != ptr_record.end());
        swap(ptr_record[ptr_loc+offset], it->second);
        //PRINTF("[HeapExpo][test]: new_ptr_addr:%016lx obj:%016lx\n", ptr_loc+offset, ptr_record[ptr_loc+offset].dst_obj);
        ptr_record.erase(it);

    }



    
    dealloc_hook_(oldptr);
}

/*
 * This function returns the address of the memory object
 * this ptr_val points to as long as it's with the range
 */
uintptr_t get_object_addr(uintptr_t addr) {
    auto it = memory_objects.upper_bound(addr);
    if (it == memory_objects.begin()) {
        return 0;
    }
    it--;
    int diff = addr - it->first;
    if (diff >= 0 && diff < it->second.size) {
        return it->first;
    }
    return 0;
}

inline void deregptr_(uintptr_t ptr_loc) {
    auto it = ptr_record.find(ptr_loc);
    if (it == ptr_record.end())
        return;
    auto moit = memory_objects.find(it->second.dst_obj);
    if ( moit != memory_objects.end()) {
        if (! moit->second.in_edges.erase(ptr_loc)) 
            assert (false && "deregptr in edge problem");
    }
    ptr_record.erase(it);
}

EXT_C void regptr(char* ptr_loc_, char* ptr_val_) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;
    uintptr_t ptr_val= (uintptr_t)ptr_val_;
    
    PRINTF("[HeapExpo][regptr]: loc:%016lx val:%016lx\n", ptr_loc, ptr_val);

    uintptr_t obj_addr = get_object_addr(ptr_val);
    uintptr_t ptr_obj_addr = get_object_addr(ptr_loc);
    if (obj_addr) PRINTF("This is a recorded object ptr\n");
    if (ptr_obj_addr) PRINTF("This ptr is in a recoreded object\n");
    
    deregptr_(ptr_loc);

    if (obj_addr && ptr_obj_addr) {
        memory_objects[obj_addr].in_edges.insert(ptr_loc);
        memory_objects[ptr_obj_addr].out_edges.insert(ptr_loc);
        ptr_record[ptr_loc] = pointer_info_t(ptr_val, ptr_obj_addr, obj_addr);
    }
}

EXT_C void deregptr(char* ptr_loc_) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;

    PRINTF("[HeapExpo][deregptr]: loc:%016lx\n", ptr_loc);
    deregptr_(ptr_loc);

}

#undef PRINTF
