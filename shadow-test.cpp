#include "shadow.h"
#include "assert.h"
#include "stdio.h"

int main() {
    uint64_t v = 0x13371337;
    uint64_t t = 0xdeadbeef; 
    {
        shadow<uint64_t> s;
        s.insert((uintptr_t)&t, &t);
        assert(*s.find((uintptr_t)&t) == t);
        s.insert_range((uintptr_t)&v, 2*sizeof(uintptr_t), &v);
        assert(*s.find((uintptr_t)&v) == v);
        assert(*s.find((uintptr_t)&v+8) == v);
        assert(s.find((uintptr_t)&v+0x10) == nullptr);
    }
    printf("Passed\n");
}
