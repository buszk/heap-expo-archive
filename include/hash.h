#ifndef HASH_H
#define HASH_H
#define OFFSET 2166136261
#define PRIME 16777619
#define BITS_IN_BYTE 8

static uint32_t hash_addr(uintptr_t data) {
    uint32_t hash = OFFSET;
#ifdef __x64_64__
    uint32_t nbytes = 8;
#else
    uint32_t nbytes = 4;
#endif
    for (int i = 0; i < nbytes; i++) {
        hash = hash ^
               ((data & (0xff << (BITS_IN_BYTE * i))) >> (BITS_IN_BYTE * i));
        hash = hash * PRIME;
    }
    return hash;
}

static uint32_t hash_addr_list(uintptr_t *list, size_t num) {
    uint32_t hash = 0;
    for (int i = 0; i < num; i++) {
        hash = hash ^ hash_addr(list[i]);
    }
    return hash;
}
#endif
