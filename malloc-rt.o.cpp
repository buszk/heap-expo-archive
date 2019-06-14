#include <unistd.h>
#include "rt-include.h"


EXT_C void *malloc(size_t size) {
    void *res = __malloc(size);
    alloc_hook((char*)res, size);
    return res;
}

EXT_C void free(void* ptr) {
    __free(ptr);
    dealloc_hook((char*)ptr);
}

EXT_C void *realloc(void* old_ptr, size_t new_size) {
    void *res = __realloc(old_ptr, new_size);
    realloc_hook((char*)old_ptr, (char*)res, new_size);
    return res;
}
