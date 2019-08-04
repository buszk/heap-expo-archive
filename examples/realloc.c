#include <stdlib.h>



void* my_realloc(void* ptr, size_t size) {
    ptr = realloc(ptr, size);
    return ptr;
}
int main() {

    void* p = malloc(100);
    p = my_realloc(p, 200);
    return 0;
    
}
