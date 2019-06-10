#include <cstdio>
#include <utility>
#include <map>
#include <set>
#include <unordered_map>

using namespace std;

#define EXT_C extern "C"

map<uintptr_t, size_t> memory_objects;
map<uintptr_t, set<uintptr_t>> in_edges; // map an object to those who points to it
map<uintptr_t, set<uintptr_t>> out_edges; // map an object to the objects it points to
unordered_map<uintptr_t, uintptr_t> ptr_record; // Log all all ptrs and the object addr 

void print_memory_objects() {
    printf("Objects List:\n");
    for (auto it = memory_objects.begin(); it != memory_objects.end(); it++) {
        printf("Heap Object: %016lx:%016lx\n", it->first, it->second);
    }
}

void print_edges() {
    printf("Edges List:\n");
    for (auto it = out_edges.begin(); it != out_edges.end(); it++) {
        for (uintptr_t obj: out_edges[it->first]) {
            printf("Heap Edge: %016lx->%016lx\n", it->first, obj);
        }
    }
}

EXT_C void print_heap() {
    print_memory_objects();
    print_edges();
}

/* 
 * XXX: Destructor not working because of freeing of heap memory */
void __attribute__((destructor(1000000))) fini_rt(void) {
    print_memory_objects();
    print_edges();
}

inline void alloc_hook_(uintptr_t ptr, size_t size) {
    memory_objects[ptr] = size;
}

EXT_C void alloc_hook(char* ptr_, size_t size) {
    uintptr_t ptr = (uintptr_t)ptr_;
    printf("[HeapExpo][alloc]: ptr:%016lx size:%016lx\n", ptr, size);
    alloc_hook_(ptr, size);
}

inline void dealloc_hook_(uintptr_t ptr) {
    auto it = memory_objects.find(ptr);
    if (it != memory_objects.end()) {
        memory_objects.erase(it);
    }
}

EXT_C void dealloc_hook(char* ptr_) {
    uintptr_t ptr = (uintptr_t)ptr_;
    printf("[HeapExpo][dealloc]: ptr:%016lx\n", ptr);
    dealloc_hook_(ptr);
}

EXT_C void realloc_hook(char* oldptr_, char* newptr_, size_t newsize) {
    uintptr_t oldptr = (uintptr_t)oldptr_;
    uintptr_t newptr = (uintptr_t)newptr_;
    printf("[HeapExpo][realloc]: oldptr:%016lx newptr:%016lx size:%016lx\n", oldptr, newptr, newsize);
    if (oldptr == newptr) {
        memory_objects[newptr] = newsize;
        return;
    }
    size_t oldsize = memory_objects[oldptr];
    alloc_hook_(newptr, newsize);

    out_edges[newptr] = out_edges[oldptr];
    if (!out_edges.erase(oldptr)) abort();

    /* Iterate every objects old object points to */
    for (uintptr_t obj_addr: out_edges[newptr]) {

        auto it = in_edges[obj_addr].upper_bound(oldptr);

        if (it == in_edges[obj_addr].begin()) {
            continue;
        }
        it--;

        while(*it >= oldptr && *it < oldptr+ oldsize)  {
            /* insert new loc with offset */
            in_edges[obj_addr].insert(*it-oldptr+newptr); 
            /* erase loc in old addr */
            in_edges[obj_addr].erase(it++);

        }
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
    if (diff >= 0 && diff < it->second) {
        return addr;
    }
    return 0;
}

inline void deregptr_(uintptr_t ptr_loc) {
    auto it = ptr_record.find(ptr_loc);
    if (it != ptr_record.end()) {
        if(!in_edges[it->second].erase(ptr_loc)) abort();
        ptr_record.erase(it);
    }
}

EXT_C void regptr(char* ptr_loc_, char* ptr_val_) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;
    uintptr_t ptr_val= (uintptr_t)ptr_val_;
    
    printf("[HeapExpo][regptr]: loc:%016lx val:%016lx\n", ptr_loc, ptr_val);

    uintptr_t obj_addr = get_object_addr(ptr_val);
    uintptr_t ptr_obj_addr = get_object_addr(ptr_loc);
    if (obj_addr) printf("This is a recorded object ptr\n");
    if (ptr_obj_addr) printf("This ptr is in a recoreded object\n");
    
    deregptr_(ptr_loc);

    if (obj_addr && ptr_obj_addr) {
        in_edges[obj_addr].insert(ptr_loc);
        out_edges[ptr_obj_addr].insert(obj_addr);
        ptr_record[ptr_loc] = obj_addr;
    }
}

EXT_C void deregptr(char* ptr_loc_) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;

    printf("[HeapExpo][deregptr]: loc:%016lx\n", ptr_loc);
    deregptr_(ptr_loc);

}
