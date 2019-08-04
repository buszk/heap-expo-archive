#include <stdlib.h>

int main() {
    void * a;
    void* l[10];
    for (int i = 0; i < 10; i++) {
        l[i] = malloc(10);
    }

    int i = 0;
    for (a = l[i]; i < 10; a = l[i]) {
        free(a);
        i++;
    }
}
