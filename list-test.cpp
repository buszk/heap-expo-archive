#include <stdio.h>
#include <inttypes.h>
#include <assert.h>
#include <string.h>

#include "rt-stl.h"
#include "rt-include.h"

#define i(l, s, v)\
    l.insert(v);\
    s.insert(v)

void p(he_sorted_list<uintptr_t, comp<uintptr_t>> l, he_set<uintptr_t> s) {

    assert(l.list.size() == s.size());

    auto it1 = l.list.begin();
    auto it2 = s.begin();

    while(it1 != l.list.end()) {
        assert(*it1 == *it2);
        it1++;
        it2++;
    }
    
}

int main() {

    he_sorted_list<uintptr_t, comp<uintptr_t>> l;
    he_set<uintptr_t> s;

    i(l, s, 0x7fff1f60ce30);
    p(l, s);
    i(l, s, 0x7fff1f60ce90);
    p(l, s);
    i(l, s, 0x7fff1f60ce88);
    p(l, s);
    i(l, s, 0x7fff1f60ce20);
    p(l, s);
    i(l, s, 0x7fff1f60cde8);
    p(l, s);
    i(l, s, 0x7fff1f60cde0);
    p(l, s);
    i(l, s, 0x7fff1f60ce18);
    p(l, s);

    printf("Success\n");
}
