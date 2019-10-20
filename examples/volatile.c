#include <stdlib.h>
#include <stdio.h>
int main() {
    char* p;
    p = malloc(10);
    *p = 'c';
    free(p);
    char c = *p;
    //printf("%c\n", c);
}
