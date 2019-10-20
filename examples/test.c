#include <stdio.h>
#include <stdlib.h>
int main() {
    char* a;
    a = malloc(8);
    free(a);
    printf("%s\n", a);
}
