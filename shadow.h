#include <assert.h>
#include "rt-include.h"
template<class T>
class shadow {

    typedef struct node {
        union {
            node* next;
            T* data;
        } u;
    } node;

    node root[256] = {};

    void cleanup(node* list, int level) {
        if (level == sizeof(uintptr_t) -1 )
            return;
        for (int i = 0; i < 256; i++) {
            if (list[i].u.next) {
                cleanup(list[i].u.next, level + 1);
                __free(list[i].u.next);
                list[i].u.next = nullptr;
            }
        }
    }

    void mark_range(node* list, int start, int end, T* data) {
        assert(256 >= end && end >= start && start >= 0);
        for (int i  = start; i < end; i++) {
            list[i] = data;
        }
    }

    


public:
    shadow() {}

    ~shadow() {
        cleanup(root, 0);
    }

    void insert(uintptr_t addr, T* meta);
    T* find(uintptr_t addr) ;

    void insert_range(uintptr_t addr, size_t size, T* meta);
    
    void insert_range_level(uintptr_t start, uintptr_t end, T* meta, 
            node* list, int level);

    bool covered(uintptr_t addr, size_t size) ;

};

template<class T>
void shadow<T>::insert(uintptr_t addr, T* meta) {
    node *cur = root;
    for (int i = 0; i < sizeof(uintptr_t) -1 ; i ++) {
        uint8_t c = (addr >> (sizeof (uintptr_t) - i-1)*8) & 0xff;
        if (!cur[c].u.next) {
            if (i == sizeof(uintptr_t) -2)
                cur[c].u.next = (node*)__calloc(sizeof(node), 32);
            else 
                cur[c].u.next = (node*)__calloc(sizeof(node), 256);
        }
        cur = cur[c].u.next;
    }
    uint8_t c = (addr&0xff) >> 3;
    cur[c].u.data = meta;
}

template<class T>
T* shadow<T>::find(uintptr_t addr) {
    node *cur = root;
    for (int i = 0; i < sizeof(uintptr_t) -1  ; i ++) {
        uint8_t c = (addr >>  (sizeof (uintptr_t) - i-1)*8) & 0xff;
        if (cur[c].u.next) 
            cur = cur[c].u.next;
        else 
            return NULL;
    }
    uint8_t c = (addr&0xff) >> 3;
    return cur[c].u.data;
}

inline uintptr_t compute_min(uintptr_t start, uint8_t mask, int level) {
    uintptr_t m = mask;
    for (int i = 0; i < sizeof(uintptr_t) - 1 - level; i ++) {
        m = m << 8;
    }
    uint64_t res = start >> ((sizeof(uintptr_t) - level ) *8) << ((sizeof(uintptr_t) - level ) *8);
    res += m;
    //printf("compute_min start:%lx, mask: %x, level: %d, result: %lx\n", start, mask, level, res);
    return res;
}


inline uintptr_t compute_max(uintptr_t end, uint8_t mask, int level) {
    uintptr_t m = mask;
    for (int i = 0; i < sizeof(uintptr_t) - 1 - level; i ++) {
        m = m << 8;
        m |= 0xff;
    }
    uint64_t res = end >> ((sizeof(uintptr_t) - level ) *8) << ((sizeof(uintptr_t) - level ) *8);
    res += m;
    //printf("compute_max end:%lx, mask: %x, level: %d, result: %lx\n", end, mask, level, res);
    return res;
}

template<class T>
void shadow<T>::insert_range_level(uintptr_t start, uintptr_t end, T* meta, 
                                   node* list, int level) {

    //printf("start: %lx end: %lx level: %d\n", start, end, level);
    if (level == sizeof(uintptr_t) - 1) {
        for (uint8_t i = ((start&0xff)>>3); i <= ((end&0xff)>>3); i++) {
            //printf("Writing %lx at %lx\n", meta, (start>>8<<8) + i);
            list[i].u.data = meta;
        }
        return;
    }

    node *cur = list;
    uint8_t c1 = (start >> (sizeof(uintptr_t) - 1 - level)*8 ) & 0xff;
    uint8_t c2 = (end >> (sizeof(uintptr_t) - 1 - level)*8 ) & 0xff;
    //printf("c1: %x c2: %x\n", c1, c2);
    for (int j = c1; j <= c2; j++) {
        if (!cur[j].u.next)  {
            if (level == sizeof(uintptr_t)-2) 
                cur[j].u.next = (node*)__calloc(sizeof(node), 32);
            else 
                cur[j].u.next = (node*)__calloc(sizeof(node), 256);
        }
        insert_range_level(std::max(start, compute_min(start, j, level)),
                           std::min(end, compute_max(end, j, level)),          
                           meta, cur[j].u.next, level+1);
    }
}

template<class T>
void shadow<T>::insert_range(uintptr_t addr, size_t size, T* meta) { insert_range_level(addr, addr+size-1, meta, root, 0); }
