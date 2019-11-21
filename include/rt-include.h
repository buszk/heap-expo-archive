#ifndef RT_INCLUDE_H
#define RT_INCLUDE_H
#include <new> // std::bad_alloc()
#include <mutex>

#include "rt-memcpy.h"
#include "rt-stl.h"
#include "rt-libc.h"

#define EXT_C extern "C"
#define UNUSED __attribute__((unused))

#define INT_MALLOC(ptr, type)                                                  \
    ptr = (type *)__malloc(sizeof(type));                                      \
    new (ptr) type

#if __x86_64__
#define KADDR 0xffff800000000000
#define RABIT 0x0000400000000000
#define STKBIT 0x0000200000000000
#else
#define KADDR 0xc0000000
#define RABIT 0x20000000
#define STKBIT 0x10000000
#endif

#ifdef MULTITHREADING
#include <pthread.h>
#define LOCK(mtx) mtx.lock()
#define UNLOCK(mtx) mtx.unlock()
#else
#define LOCK(mtx)
#define UNLOCK(mtx)
#endif

#define alias(name, aliasname) _alias(name, aliasname)

#define _alias(name, aliasname)                                                \
    extern __typeof(name) aliasname __attribute__((alias(#name)))              \
        __attribute_copy__(name);

extern "C" {
void msg(const char *);
void check_double_free(void *);
void alloc_hook(char *addr, size_t size);
void dealloc_hook(char *addr);
void realloc_hook(char *old_addr, char *new_addr, size_t new_size);
}

enum memory_type_e { UNKNOWN, GLOBAL, HEAP, STACK };

static const char *memory_type_strings[] = {"Unknow", "Global", "Heap",
                                            "Stack"};

UNUSED static const char *getTypeString(int typeVal) {
    return memory_type_strings[typeVal];
}

using edge_type = he_list<uintptr_t>;

struct object_info_t {
    uintptr_t addr;
    size_t size;
    memory_type_e type;
    uint32_t signature;
    edge_type in_edges;
    edge_type out_edges;
    bool released;
    bool copied;
#ifdef MULTITHREADING
    std::mutex in_mutex;
    std::mutex out_mutex;
#endif

    object_info_t() {
        addr = 0;
        size = 0;
        type = UNKNOWN;
        signature = 0;
        in_edges = {};
        out_edges = {};
        released = false;
        copied = false;
    }

    object_info_t(uintptr_t a, size_t s) {
        addr = a;
        size = s;
        type = UNKNOWN;
        signature = 0;
        in_edges = {};
        out_edges = {};
        released = false;
        copied = false;
    }

    /* For global_hook */
    object_info_t(uintptr_t a, size_t s, memory_type_e t) {
        addr = a;
        size = s;
        type = t;
        in_edges = {};
        out_edges = {};
        released = false;
        copied = false;
    }

    /* For alloc_hook */
    object_info_t(uintptr_t a, size_t s, memory_type_e t, uint32_t sig) {
        addr = a;
        size = s;
        type = t;
        signature = sig;
        in_edges = {};
        out_edges = {};
        released = false;
    }

    object_info_t &operator=(const object_info_t &copy) {
        memset(this, 0, sizeof(object_info_t));
        addr = copy.addr;
        size = copy.size;
        type = copy.type;
        /*
        in_edges = {};
        out_edges = {};
        */
        new (&in_edges) edge_type;
        new (&out_edges) edge_type;
#ifdef MULTITHREADING
        new (&in_mutex) std::mutex;
        new (&out_mutex) std::mutex;
#endif
        signature = copy.signature;
        released = false;
        copied = false;
        return *this;
    }
};

struct pointer_info_t {
    uintptr_t loc, value, src_obj, dst_obj;
    bool invalid;
    struct object_info_t *src_info, *dst_info;
    edge_type::iterator src_it, dst_it;
    uint32_t id;

    pointer_info_t() {
        loc = value = src_obj = dst_obj = invalid = id = 0;
        src_info = dst_info = NULL;
    }

    pointer_info_t(uintptr_t l, uintptr_t v) {
        loc = l;
        value = v;
        src_obj = dst_obj = invalid = id = 0;
        src_info = dst_info = NULL;
    }

    pointer_info_t(uintptr_t l, uintptr_t v, uintptr_t s, uintptr_t d,
                   struct object_info_t *si, struct object_info_t *di,
                   edge_type::iterator sit, edge_type::iterator dit,
                   uint32_t i) {
        loc = l;
        value = v;
        src_obj = s;
        dst_obj = d;
        src_info = si;
        dst_info = di;
        src_it = sit;
        dst_it = dit;
        id = i;
        invalid = 0;
    }

    pointer_info_t(const pointer_info_t &copy) {
        loc = copy.loc;
        value = copy.value;
        src_obj = copy.src_obj;
        dst_obj = copy.dst_obj;
        src_info = copy.src_info;
        dst_info = copy.dst_info;
        src_it = copy.src_it;
        dst_it = copy.dst_it;
        invalid = copy.invalid;
        id = copy.id;
    }
};

struct residual_pointer_t {
    uintptr_t loc;
    uintptr_t val;
    uint32_t src_sig;
    uint32_t dst_sig;
    uint32_t free_sig;
    uint32_t store_id;
    int32_t counter;
    int32_t adj_cnt;

    residual_pointer_t(uintptr_t l, uintptr_t v, uint32_t s, uint32_t d,
                       uint32_t f, uint32_t id, int32_t c) {
        loc = l;
        val = v;
        src_sig = s;
        dst_sig = d;
        free_sig = f;
        store_id = id;
        counter = c;
        adj_cnt = c;
    }
};

bool cntcmp(residual_pointer_t &a, residual_pointer_t &b) {
    return a.adj_cnt < b.adj_cnt;
}

struct stack_pointer_t {
    uintptr_t loc;
    uintptr_t val;
    object_info_t *dst_info;
    uint32_t store_id;

    stack_pointer_t(uintptr_t l) {
        loc = l;
        val = store_id = 0;
        dst_info = nullptr;
    }

    stack_pointer_t(uintptr_t l, uintptr_t v, object_info_t *di, uint32_t id) {
        loc = l;
        val = v;
        dst_info = di;
        store_id = id;
    }
};

template <class T> struct comp;
template <> struct comp<stack_pointer_t> {
    long int diff(const stack_pointer_t &x, const stack_pointer_t &y) const {
        return x.loc - y.loc;
    }
};

template <class T> struct comp {
    long int diff(const T &x, const T &y) const { return x - y; }
};

#endif
