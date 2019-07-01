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
#include <iostream>
#include <string>
#include <vector>

using namespace std;

vector<string> strings;

string* history[5] = {0};
int history_ind = 0;

int main(int argc, char** argv) {

    string buf;

    while (1) {
        cout << "Give me a string: " << endl;
        if (!getline(cin, buf))
            break;

        if (buf.find("quit") != string::npos) 
            break;

        strings.push_back(buf);
        history[history_ind++%5] = &strings[strings.size()-1];
    }
    cout << "Here are your strings:\n";
    for (string s : strings) {
        cout << s << "\n";
    }

    strings.clear();

    exit(0);
}
