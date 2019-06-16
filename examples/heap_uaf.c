#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define BUFSIZE   512
    
int main(int argc, char **argv) {   

    char **list = (char**) malloc(sizeof(char*) *3);

    list[0] = (char *) malloc(BUFSIZE);
    list[1] = (char *) malloc(BUFSIZE);

    free(list[1]);

    list[2] = (char *) malloc(BUFSIZE);
    char c = *list[1];

}
