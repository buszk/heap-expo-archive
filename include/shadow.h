#include <assert.h>
#include <unistd.h>
#include "rt-include.h"
#include <mutex>

#define NUM_CHILD 256
#ifdef __x86_64__ // 48-bit addressing
#define PTR_BYTES 6
#define PTR_BITS 48
#define LAST_NUM_CHILD 32
#else 
#define PTR_BYTES 4
#define PTR_BITS 32
#define LAST_NUM_CHILD 64
#endif

#define NUM_CHILD_LEVEL(x)              ((x==PTR_BYTES-1) ? LAST_NUM_CHILD : NUM_CHILD)

#define PTR_LAST_INDEX(ptr)             ((ptr & 0xff) >> 3)
#define GET_PTR_BYTE(b, ptr, n)         b = (ptr >> (PTR_BYTES - n - 1)*8) & 0xff
#define GET_PTR_LAST_INDEX(b, ptr)      b = ((ptr & 0xff) >> 3)
#ifdef DEBUG
#define LIST_OVERFLOW_CHECK(l, i)       if (l!=root && malloc_usable_size(l)/sizeof(node) <= i) assert(false)
#else
#define LIST_OVERFLOW_CHECK(l, i)
#endif
#define LIST_NODE(l, i)                 l[i]
#define LIST_NODE_NEXT(l, i)            l[i].u.next
#define LIST_NODE_DATA(l, i)            l[i].u.data
#define LIST_NODE_LEAF(l, i)            l[i].leaf
#define SET_LIST_NODE_NEXT(l, i, v)     LIST_OVERFLOW_CHECK(l, i); l[i].u.next = v
#define SET_LIST_NODE_DATA(l, i, v)     LIST_OVERFLOW_CHECK(l, i); l[i].u.data = v
#define SET_LIST_NODE_LEAF(l, i, v)     LIST_OVERFLOW_CHECK(l, i); l[i].leaf = v
#define GET_LIST_NODE_NEXT(r, l, i)     LIST_OVERFLOW_CHECK(l, i); r = l[i].u.next
#define GET_LIST_NODE_DATA(r, l, i)     LIST_OVERFLOW_CHECK(l, i); r = l[i].u.data
#define GET_LIST_NODE_LEAF(r, l, i)     LIST_OVERFLOW_CHECK(l, i); r = l[i].leaf

#define INIT_LIST_NODE_NEXT(l, i, n)    l[i].u.next = (node*)__calloc(sizeof(node), n)

#ifdef MULTITHREADING
#define LIST_NODE_LOCK(l, i)            l[i].lock.lock()
#define LIST_NODE_UNLOCK(l, i)          l[i].lock.unlock()
#endif

extern "C" size_t malloc_usable_size (void *ptr);

/*
template <class T>
class __allocator {
    std::list<void*> pages;
    void*  cur_page;
    T*     cur_place;
    size_t cur_space;

    T* allocate(size_t n) {
        T *res;
        if (cur_page && cur_space >= n) {
            res = cur_place;
            cur_place += n;
            cur_space -= n;
            return res;
        }
        else {
            cur_page = mmap();
        }
    }
    void deallocate(T* ptr, size_t n)
}*/

template<class T>
class shadow {

    typedef struct node {
        union {
            node* next;
            T* data;
        } u;
        uint8_t leaf;
#ifdef MULTITHREADING
        std::mutex lock; // lock for pointer
#endif
    } node;

    node root[NUM_CHILD] = {};

    void cleanup(node* list, int level) {
        //printf("cleanup %lx[%x] level: %d\n", list, NUM_CHILD_LEVEL(level), level);
        if (level == PTR_BYTES -1 )
            return;
        for (uint32_t i = 0; i < NUM_CHILD_LEVEL(level); i++) {
            //printf("%d ", i);
            LIST_OVERFLOW_CHECK(list, i);
            if (LIST_NODE_LEAF(list, i))
                continue;
            else if (LIST_NODE_NEXT(list, i)) {
                //printf("%d \n", i);
                //printf("cleanup %lx[%x/%x] level: %d\n", list[i].u.next, i,NUM_CHILD_LEVEL(level +1), level+1);
                cleanup(LIST_NODE_NEXT(list, i), level + 1);
                //printf("freeing %lx\n", list[i].u.next);
                __free(LIST_NODE_NEXT(list, i));
                SET_LIST_NODE_NEXT(list, i, nullptr);
            }
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
    uint8_t c;
    for (int i = 0; i < PTR_BYTES -1 ; i ++) {
        GET_PTR_BYTE(c, addr, i);
        LIST_OVERFLOW_CHECK(cur, c);
        if (!LIST_NODE_NEXT(cur, c)) {
#ifdef MULTITHREADING
            LIST_NODE_LOCK(cur, c);
            if (!LIST_NODE_NEXT(cur, c)) {
#endif
                INIT_LIST_NODE_NEXT(cur, c, NUM_CHILD_LEVEL(i+1));
                SET_LIST_NODE_LEAF(cur, c, 0);
#ifdef MULTITHREADING
            }
            LIST_NODE_UNLOCK(cur, c);
#endif
        }
        GET_LIST_NODE_NEXT(cur, cur, c);
    }
    GET_PTR_LAST_INDEX(c, addr);
    SET_LIST_NODE_DATA(cur, c, meta);
    SET_LIST_NODE_LEAF(cur, c, (meta!=nullptr));
}

template<class T>
T* shadow<T>::find(uintptr_t addr) {
    node *cur = root;
    uint8_t c;
    for (int i = 0; i < PTR_BYTES -1  ; i ++) {
        GET_PTR_BYTE(c, addr, i);
        LIST_OVERFLOW_CHECK(cur, c);
        if (LIST_NODE_LEAF(cur, c)) {
            return LIST_NODE_DATA(cur, c);
        }
        else if (LIST_NODE_NEXT(cur, c))  {
            GET_LIST_NODE_NEXT(cur, cur, c);
        }
        else {
            return NULL;
        }
    }
    GET_PTR_LAST_INDEX(c, addr);
    LIST_OVERFLOW_CHECK(cur, c);
    return LIST_NODE_DATA(cur, c);
}

inline uintptr_t compute_min(uintptr_t start, uint8_t mask, int level) {
    uintptr_t m = mask;
    for (int i = 0; i < PTR_BYTES - 1 - level; i ++) {
        m = m << 8;
    }
    uint64_t res = start >> ((PTR_BYTES - level ) *8) << ((PTR_BYTES - level ) *8);
    res += m;
    //printf("compute_min start:%lx, mask: %x, level: %d, result: %lx\n", start, mask, level, res);
    return res;
}


inline uintptr_t compute_max(uintptr_t end, uint8_t mask, int level) {
    uintptr_t m = mask;
    for (int i = 0; i < PTR_BYTES - 1 - level; i ++) {
        m = m << 8;
        m |= 0xff;
    }
    uint64_t res = end >> ((PTR_BYTES - level ) *8) << ((PTR_BYTES - level ) *8);
    res += m;
    //printf("compute_max end:%lx, mask: %x, level: %d, result: %lx\n", end, mask, level, res);
    return res;
}

template<class T>
void shadow<T>::insert_range_level(uintptr_t start, uintptr_t end, T* meta, 
                                   node* list, int level) {

    uint8_t c1, c2;

    //printf("start: %lx end: %lx level: %d\n", start, end, level);
    if (level == PTR_BYTES - 1) {
        for (uint8_t i = PTR_LAST_INDEX(start); i <= PTR_LAST_INDEX(end); i++) {
            //printf("Writing %lx at %lx\n", meta, (start>>8<<8) + i);
            SET_LIST_NODE_DATA(list, i, meta);
            SET_LIST_NODE_LEAF(list, i, (meta!=nullptr));
        }
        return;
    }

    node *cur = list;
    GET_PTR_BYTE(c1, start, level);
    GET_PTR_BYTE(c2, end, level);
    //printf("c1: %x c2: %x\n", c1, c2);
    for (int j = c1; j <= c2; j++) {
        if (start == compute_min(start, j, level) 
                && end == compute_max(end, j, level)) {
            // XXX
            cleanup(LIST_NODE_NEXT(cur, j), level+1);
            SET_LIST_NODE_DATA(cur, j, meta);
            SET_LIST_NODE_LEAF(cur, j, (meta!=nullptr));
            //char str[] = "shallow:  \n";
            //str[9] = level+'0';
            //write(2, str , sizeof(str));
            continue;
        }
        LIST_OVERFLOW_CHECK(cur, j);
        if (LIST_NODE_LEAF(cur, j)) {
            assert( list!=nullptr && "Overwrite a leaf node in non-bottom level");
            SET_LIST_NODE_DATA(list, j, meta);
            SET_LIST_NODE_LEAF(list, j, (meta!=nullptr));
            continue;
        }
        else if(!LIST_NODE_NEXT(cur, j)) {
#ifdef MULTITHREADING
            LIST_NODE_LOCK(cur, j);
            //write(2, "lock\n", 5);
            if (!LIST_NODE_NEXT(cur, j)) {
#endif
                INIT_LIST_NODE_NEXT(cur, j, NUM_CHILD_LEVEL(level+1));
                SET_LIST_NODE_LEAF(cur, j, 0);
#ifdef MULTITHREADING
            }
            LIST_NODE_UNLOCK(cur, j);
            //write(2, "unlock\n", 7);
#endif
        }
        insert_range_level(std::max(start, compute_min(start, j, level)),
                           std::min(end, compute_max(end, j, level)),          
                           meta, LIST_NODE_NEXT(cur, j), level+1);
    }
}

template<class T>
void shadow<T>::insert_range(uintptr_t addr, size_t size, T* meta) { 
    insert_range_level(addr, addr+size-1, meta, root, 0); 
}
