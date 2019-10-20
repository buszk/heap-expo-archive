#ifndef _GNU_SROUCE
#define _GNU_SOURCE 1
#endif
#ifdef HEAP_EXPO_RT
#ifndef RT_MEMCPY_H
#define RT_MEMCPY_H
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
extern "C" void memcpy_hook(char*, char*, size_t);

#ifdef memcpy
#undef memcpy
#define memcpy memcpy
#endif

extern "C" 
void* memcpy(void* dst, const void* src, size_t num) noexcept {
    static void*(*__memcpy)(void*, const void*, size_t) = NULL;
    if (!__memcpy) {
        __memcpy = (void* (*)(void*, const void*, size_t)) dlsym(RTLD_NEXT, "memcpy");
        if (!__memcpy) {
            fprintf(stderr, "Error in `dlsym`: %s\n", dlerror());
            exit(1);
        }
    }
    __memcpy(dst, src, num);
    memcpy_hook((char*)dst, (char*)src, num);
    return NULL;
}
#undef memcpy
#define memcpy __memcpy
#endif
#endif
