#include <cstdio>
#include <utility>
#include <map>
#include <set>
#include <unordered_map>

using namespace std;

map<uintptr_t, size_t> memory_objects;
map<uintptr_t, set<uintptr_t>> in_edges; // map an object to those who points to it
map<uintptr_t, set<uintptr_t>> out_edges; // map an object to the objects it points to
unordered_map<uintptr_t, uintptr_t> ptr_record; // Log all all ptrs and the object addr 

inline void alloc_hook_(void* ptr_, size_t size) {
    uintptr_t ptr = (uintptr_t)ptr_;
    memory_objects[ptr] = size;
}

void alloc_hook(void* ptr_, size_t size) {
    alloc_hook_(ptr_, size);
}

inline void dealloc_hook_(void* ptr_) {
    uintptr_t ptr = (uintptr_t)ptr_;
    auto it = memory_objects.find(ptr);
    if (it != memory_objects.end()) {
        memory_objects.erase(it);
    }
}

void dealloc_hook(void* ptr_) {
    dealloc_hook_(ptr_);
}

void realloc_hook(void* oldptr_, void* newptr_, size_t newsize) {
    uintptr_t oldptr = (uintptr_t)oldptr_;
    uintptr_t newptr = (uintptr_t)newptr_;
    if (oldptr == newptr) {
        memory_objects[newptr] = newsize;
        return;
    }
    size_t oldsize = memory_objects[oldptr];
    alloc_hook_(newptr_, newsize);

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

    dealloc_hook_(oldptr_);
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

extern "C" void regptr(char* ptr_loc_, char* ptr_val_) {
    uintptr_t ptr_loc = (uintptr_t)ptr_loc_;
    uintptr_t ptr_val= (uintptr_t)ptr_val_;
    
    printf("[HeapExpo][regptr]: loc:%016lx val:%016lx\n", ptr_loc, ptr_val);

    uintptr_t obj_addr = get_object_addr(ptr_val);
    uintptr_t ptr_obj_addr = get_object_addr(ptr_loc);
    if (obj_addr) printf("This is a recorded object ptr\n");
    if (ptr_obj_addr) printf("This ptr is in a recoreded object\n");
    auto it = ptr_record.find(ptr_loc);
    /* We remove the previous record if exists */
    if (it != ptr_record.end()) {
        if(!in_edges[it->second].erase(ptr_loc)) abort();
        ptr_record.erase(it);
    }

    if (obj_addr && ptr_obj_addr) {
        in_edges[obj_addr].insert(ptr_loc);
        out_edges[ptr_obj_addr].insert(obj_addr);
        ptr_record[ptr_loc] = obj_addr;
    }
}
