#ifndef RT_LIBC_H
#define RT_LIBC_H
#define __malloc __libc_malloc
#define __free __libc_free
#define __calloc __libc_calloc
#define __realloc __libc_realloc
#define __aligned_alloc __libc_aligned_alloc
#define __memalign __libc_memalign
#define __pvalloc __libc_pvalloc
#define __valloc __libc_valloc
extern "C" {
void *__libc_malloc(size_t);
void __libc_free(void *);
void *__libc_calloc(size_t, size_t);
void *__libc_realloc(void *, size_t);
void *__libc_memalign(size_t, size_t);
void *__libc_aligned_alloc(size_t, size_t);
void *__libc_valloc(size_t);
void *__libc_pvalloc(size_t);
int __posix_memalign(void **, size_t, size_t);
}
#endif
