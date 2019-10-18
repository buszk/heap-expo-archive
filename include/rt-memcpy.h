#ifndef _GNU_SROUCE
#define _GNU_SOURCE 1
#endif
#include <stdio.h>
#include <dlfcn.h>
extern "C" void memcpy_hook(char*, char*, size_t);

extern "C" void* memcpy(void* dst, const void* src, size_t num) {
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

extern "C" void* memset(void*s, int c, size_t n);
