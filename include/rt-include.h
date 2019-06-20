#include <new>  // std::bad_alloc()
#include <vector>
#include <set>
#include <unordered_set>
#include <map>
#include <unordered_map>
#include <mutex>

#define EXT_C extern "C"

#define __malloc            __libc_malloc
#define __free              __libc_free
#define __calloc            __libc_calloc
#define __realloc           __libc_realloc
#define __aligned_alloc     __libc_aligned_alloc
#define __memalign          __libc_memalign
#define __pvalloc           __libc_pvalloc
#define __valloc            __libc_valloc

#define alias(name, aliasname) _alias(name, aliasname)

#define _alias(name, aliasname) \
    extern __typeof (name) aliasname __attribute__((alias(#name))) \
        __attribute_copy__(name);

extern "C" {
    void msg(const char*);
    void alloc_hook(char* addr, size_t size);
    void dealloc_hook(char* addr);
    void realloc_hook(char* old_addr, char* new_addr, size_t new_size);

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

enum memory_type_e { UNKNOWN, GLOBAL, HEAP, STACK };

static const char* memory_type_strings[] = { "Unknow", "Global", "Heap", "Stack" };

static const char* getTypeString(int typeVal) {
    return memory_type_strings[typeVal];
}

struct object_info_t {
    size_t                      size      ;
    memory_type_e               type      ;
    he_unordered_set<uintptr_t> in_edges  ;
    std::mutex                  in_mutex  ;
    he_unordered_set<uintptr_t> out_edges ;
    std::mutex                  out_mutex ;
    
    object_info_t () {
        size = 0;
        type = UNKNOWN;
        in_edges = {};
        out_edges = {};
    }

    object_info_t (size_t s) {
        size = s;
        type = UNKNOWN;
        in_edges = {};
        out_edges = {};
    }

    object_info_t (size_t s, memory_type_e t) {
        size = s;
        type = t;
        in_edges = {};
        out_edges = {};
    }
/*
    object_info_t (object_info_t &copy) {
        size = copy.size;
        type = copy.type;
    }
*/
};

struct pointer_info_t {
    uintptr_t             value    ,
                          src_obj  ,
                          dst_obj  ;
    bool                  invalid  ;
    struct object_info_t *src_info ,
                         *dst_info ;

    pointer_info_t () {
        value = src_obj = dst_obj = invalid = 0;
        src_info = dst_info = NULL;
    }

    pointer_info_t (uintptr_t v) {
        value = v;
        src_obj = dst_obj = invalid = 0;
        src_info = dst_info = NULL;
    }

    pointer_info_t (uintptr_t v, uintptr_t s, uintptr_t d,
            struct object_info_t *si, struct object_info_t *di) {
        value = v;
        src_obj = s;
        dst_obj = d;
        src_info = si;
        dst_info = di;
        invalid = 0;
    } 

};
