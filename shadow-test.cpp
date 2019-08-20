#include "shadow.h"
#include "assert.h"
#include "stdio.h"

uintptr_t a = 0x19999999;
int main() {
    uint64_t v = 0x13371337;
    uint64_t t = 0xdeadbeef; 
    uint64_t t2 = 0x11111111;
    {
        shadow<uint64_t> s;
        s.insert((uintptr_t)&t, &t);
        assert(*s.find((uintptr_t)&t) == t);
        s.insert_range((uintptr_t)&v, 2*sizeof(uintptr_t), &v);
        assert(*s.find((uintptr_t)&v) == v);
        assert(*s.find((uintptr_t)&v+8) == v);
        assert(s.find((uintptr_t)&v+0x10) == nullptr);
        s.insert_range(0x3735afd0, 0x1f9c0, &a);
        assert(s.find(0x37370000) == &a);
        assert(s.find(0x3737A800) == &a);
        assert(s.find(0x37360000) == &a);
        s.insert_range(0x3735afd0, 0x1f9c0, nullptr);
        assert(s.find(0x37370000) == nullptr);
        assert(s.find(0x3737A800) == nullptr);
        assert(s.find(0x37360000) == nullptr);

    }
    printf("Passed\n");
}
