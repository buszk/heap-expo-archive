#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define BUFSIZE   512

int main(int argc, char **argv) {   
    
    char *p1;
    char *p2;

    p1 = malloc(8);
    if (p1)
        free(p1);

}
