#ifndef RT_INCLUDE_H
#define RT_INCLUDE_H
#include <new>  // std::bad_alloc()
#include <vector>
#include <set>
#include <unordered_set>
#include <map>
#include <list>
#include <unordered_map>
#include <shared_mutex>

#define EXT_C extern "C"

#define __malloc            __libc_malloc
#define __free              __libc_free
#define __calloc            __libc_calloc
#define __realloc           __libc_realloc
#define __aligned_alloc     __libc_aligned_alloc
#define __memalign          __libc_memalign
#define __pvalloc           __libc_pvalloc
#define __valloc            __libc_valloc

#define INT_MALLOC(ptr, type) \
    ptr = (type*)__malloc(sizeof(type)); \
    new(ptr) type

#if __x86_64__
#define KADDR 0xffff800000000000
#else
#define KADDR 0xc0000000
#endif
    

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

#define alias(name, aliasname) _alias(name, aliasname)

#define _alias(name, aliasname) \
    extern __typeof (name) aliasname __attribute__((alias(#name))) \
        __attribute_copy__(name);

extern "C" {
    void msg(const char*);
    void alloc_hook(char* addr, size_t size);
    void dealloc_hook(char* addr);
    void realloc_hook(char* old_addr, char* new_addr, size_t new_size);

    void check_double_free(void*);

    void *__libc_malloc(size_t);
    void __libc_free(void*);
    void *__libc_calloc(size_t, size_t);
    void *__libc_realloc(void*, size_t);
    void *__libc_memalign(size_t, size_t);
    void *__libc_aligned_alloc(size_t, size_t);
    void *__libc_valloc(size_t);
    void *__libc_pvalloc(size_t);
    int  __posix_memalign(void**, size_t, size_t);
}

template <typename T>
class he_allocator {
public:
    typedef T value_type;
    he_allocator() = default;
    
    template <typename U> constexpr 
    he_allocator(const he_allocator<U>&) noexcept {}

    T* allocate(size_t n) {
        if(n > size_t(-1) / sizeof(T)) throw std::bad_alloc();
        if(auto p = static_cast<T*>(__malloc(n*sizeof(T)))) return p;
        throw std::bad_alloc();
    };

    template <typename U>
    bool operator==(const he_allocator<U>&) {return true;}
    
    template <typename U>
    bool operator!=(const he_allocator<U>&) {return false;}

    void deallocate(T* p, std::size_t) noexcept { __free(p); }
};

template <typename T>
using he_vector = std::vector<T, he_allocator<T>>;

template <typename T>
using he_set = std::set<T, std::less<T>, he_allocator<T>>;

template <typename T>
using he_unordered_set = std::unordered_set<T, std::hash<T>, std::equal_to<T>, he_allocator<T>>;

template <typename Key, typename T>
using he_map = std::map<Key, T, std::less<Key>, he_allocator<std::pair<const Key, T>>>;

template <typename Key, typename T>
using he_unordered_map = std::unordered_map<Key, T, std::hash<Key>, std::equal_to<Key>, he_allocator<std::pair<const Key, T>>>;

template <typename T>
using he_list = std::list<T, he_allocator<T>>;

enum memory_type_e { UNKNOWN, GLOBAL, HEAP, STACK };

static const char* memory_type_strings[] = { "Unknow", "Global", "Heap", "Stack" };

static const char* getTypeString(int typeVal) {
    return memory_type_strings[typeVal];
}

using edge_type = he_unordered_set<uintptr_t>;
using stack_edge_type = he_unordered_map<uintptr_t, uint32_t>;

struct object_info_t {
    uintptr_t                   addr      ;
    size_t                      size      ;
    memory_type_e               type      ;
    uint32_t                    signature ;
    edge_type                   in_edges  ;
    edge_type                   out_edges ;
    stack_edge_type             stack_edges ;
#ifdef MULTITHREADING
    std::shared_mutex           in_mutex  ;
    std::shared_mutex           out_mutex ;
    std::shared_mutex           stack_mutex ;
#endif
    
    object_info_t () {
        addr = 0;
        size = 0;
        type = UNKNOWN;
        signature = 0;
        in_edges = {};
        out_edges = {};
        stack_edges = {};
    }

    object_info_t (uintptr_t a, size_t s) {
        addr = a;
        size = s;
        type = UNKNOWN;
        signature = 0;
        in_edges = {};
        out_edges = {};
        stack_edges = {};
    }

    /* For global_hook */
    object_info_t (uintptr_t a, size_t s, memory_type_e t) {
        addr = a;
        size = s;
        type = t;
        in_edges = {};
        out_edges = {};
        stack_edges = {};
    }

    /* For alloc_hook */
    object_info_t (uintptr_t a, size_t s, memory_type_e t, uint32_t sig) {
        addr = a;
        size = s;
        type = t;
        signature = sig;
        in_edges = {};
        out_edges = {};
        stack_edges = {};
    }
    
    object_info_t &operator=(const object_info_t &copy) {
        addr = copy.addr;
        size = copy.size;
        type = copy.type;
        /*
        in_edges = {};
        out_edges = {};
        stack_edges = {};
        */
        new(&in_edges) edge_type;
        new(&out_edges) edge_type;
        new(&stack_edges) stack_edge_type;
        signature = copy.signature;
        return *this;
    }
};

struct pointer_info_t {
    uintptr_t             value    ,
                          src_obj  ,
                          dst_obj  ;
    bool                  invalid  ;
    struct object_info_t *src_info ,
                         *dst_info ;
    uint32_t              id       ;

    pointer_info_t () {
        value = src_obj = dst_obj = invalid = id = 0;
        src_info = dst_info = NULL;
    }

    pointer_info_t (uintptr_t v) {
        value = v;
        src_obj = dst_obj = invalid = id = 0;
        src_info = dst_info = NULL;
    }

    pointer_info_t (uintptr_t v, uintptr_t s, uintptr_t d,
            struct object_info_t *si, struct object_info_t *di, uint32_t i) {
        value = v;
        src_obj = s;
        dst_obj = d;
        src_info = si;
        dst_info = di;
        id = i;
        invalid = 0;
    } 

    pointer_info_t (const pointer_info_t &copy) {
        value = copy.value;
        src_obj = copy.src_obj;
        dst_obj = copy.dst_obj;
        src_info = copy.src_info;
        dst_info = copy.dst_info;
        invalid = copy.invalid;
        id = copy.id;
    }

};

struct residual_pointer_t {
    uintptr_t     loc      ;
    uintptr_t     val      ;
    uint32_t      src_sig  ;
    uint32_t      dst_sig  ;
    uint32_t      free_sig ;
    uint32_t      store_id ;
    int32_t       counter  ;
    int32_t       adj_cnt  ;

    residual_pointer_t (uintptr_t l, uintptr_t v, uint32_t s, uint32_t d,
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

bool cntcmp(residual_pointer_t a, residual_pointer_t b) {
    return a.adj_cnt < b.adj_cnt;
}

struct stack_pointer_t {
    uintptr_t     loc      ;
    uint32_t      store_id ;

    stack_pointer_t (uintptr_t l, uint32_t id) {
        loc = l;
        id = store_id;
    }
};

#endif
