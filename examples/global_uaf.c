#include <stdio.h>
#include <unistd.h>
#include <string.h>

#define BUFSIZE   512
    
char *buf1;
char *buf2;
char *buf3;

int main(int argc, char **argv) {   

    buf1 = (char *) malloc(BUFSIZE);
    buf2 = (char *) malloc(BUFSIZE);

    free(buf2);

    buf3 = (char *) malloc(BUFSIZE);
    char c = *buf2;

}
