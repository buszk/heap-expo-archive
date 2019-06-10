#include <new>  // std::bad_alloc()
#include <vector>
#include <set>
#include <unordered_set>
#include <map>
#include <unordered_map>

#define EXT_C extern "C"

#define __malloc   __libc_malloc
#define __free     __libc_free
#define __calloc   __libc_calloc
#define __realloc  __libc_realloc

extern "C" {
    void alloc_hook(char* addr, size_t size);
    void dealloc_hook(char* addr);
    void realloc_hook(char* old_addr, char* new_addr, size_t new_size);

    void *__libc_malloc(size_t);
    void __libc_free(void*);
    void *__libc_calloc(size_t, size_t);
    void *__libc_realloc(void*, size_t);
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

