#include <unistd.h>
#include <errno.h>
#include "rt-include.h"

#define powerof2(x)     ((((x) - 1) & (x)) == 0)

EXT_C void *malloc(size_t size) {
    void *res = __malloc(size);
    alloc_hook((char*)res, size);
    return res;
}

EXT_C void* calloc(size_t num, size_t size) {
    void *res = __calloc(num, size);
    alloc_hook((char*)res, num*size);
    return res;
}

EXT_C void free(void* ptr) {
    __free(ptr);
    dealloc_hook((char*)ptr);
}

EXT_C void* realloc(void* old_ptr, size_t new_size) {
    void *res = __realloc(old_ptr, new_size);
    realloc_hook((char*)old_ptr, (char*)res, new_size);
    return res;
}

EXT_C void* memalign(size_t alignment, size_t bytes) {
    void *res = __memalign(alignment, bytes);
    msg("[memalign]");
    alloc_hook((char*)res, bytes);
    return res;
}

EXT_C void* aligned_alloc(size_t alignment, size_t bytes) {
    void *res = __memalign(alignment, bytes);
    msg("[aligned_alloc]");
    alloc_hook((char*)res, bytes);
    return res;
}

EXT_C void* valloc(size_t size) {
    void *res = __valloc(size);
    msg("[valloc]");
    alloc_hook((char*)res, size);
    return res;
}

EXT_C void* pvalloc(size_t size) {
    void *res = __pvalloc(size);
    msg("[pvalloc]");
    alloc_hook((char*)res, size);
    return res;
}
/*
EXT_C int posix_memalign(void** memptr, size_t alignment, size_t size) {
    void *mem;
    msg("[posix_memalign]");
    // Test whether the SIZE argument is valid.  It must be a power of
    // two multiple of sizeof (void *).  
    if (alignment % sizeof (void *) != 0
          || !powerof2 (alignment / sizeof (void *))
          || alignment == 0)
      return EINVAL;
    mem = __memalign (alignment, size);
    if (mem != NULL) {
        *memptr = mem;
        alloc_hook((char*)mem, size);
        return 0;
    }
    return ENOMEM;
}*/
