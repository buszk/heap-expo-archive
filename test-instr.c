/*
   american fuzzy lop - a trivial program to test the build
   --------------------------------------------------------

   Written and maintained by Michal Zalewski <lcamtuf@google.com>

   Copyright 2014 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>


char** strings = 0;
size_t size = 0;
size_t capacity = 0;

void print_heap();

int main(int argc, char** argv) {

  char buf[16] = {0};
  int res;

  while (1) {
    printf("Give me a string:\n");
    if ((res = read(1, buf, 16))) {
      buf[res-1] = 0; // remove next line character
      if (!strcmp(buf, "quit")) break;
      if (size == capacity) {
        capacity = capacity*2 +1;
        strings = realloc(strings, capacity*sizeof(char*));
      }
      char* tmp = malloc(res+1);
      memcpy(tmp, buf, res);
      strings[size++] = tmp;
    }
  }
  print_heap();
  printf("Here are your strings:\n");
  for (int i = 0; strings && strings[i] && i < size; i++) {
    printf("%s\n", strings[i]);
    //free(strings[i]);
  }
  strings = 0;


  exit(0);

}
