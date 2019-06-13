#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "\n"
            "This is a helper application for heap exposure. It serves as a drop-in\n"
            "replacement for clang, letting you recompile third-party code with the\n"
            "required runtime instrumentation.\n\n";
        return 1;
    }

    std::vector<std::string> params;
    char *path = getenv("HEAP_EXPO_PATH");

    std::string argv0(argv[0]);
    std::string obj_path;
    bool maybe_linking = true;

    if (path) {
        obj_path = std::string(path);
    }
    else {
        obj_path = argv0.substr(0,
                argv0.find_last_of('/'));
    }

    std::cout << "Object path: " << obj_path << '\n';

    params.push_back("-Xclang");
    params.push_back("-load");
    params.push_back("-Xclang");
    params.push_back(obj_path + "/LLVMHeapExpo.so");

    if (argc == 1 && !strcmp(argv[1], "-v")) maybe_linking = false;
    int argc_ = argc;
    char** argv_ = argv;
    while (--argc_) {
        std::string cur(*(++argv_));
        
        if (cur == "-c" || cur == "-S" || cur == "-E")
            maybe_linking = false;

    }
    /* force c++ because rt uses STL lib */
    params.push_back("-lstdc++"); 
    if (maybe_linking) {
        params.push_back("-flto");
        params.push_back(obj_path + "/heap-expo-rt.o");
        params.push_back(obj_path + "/malloc-rt.o");
    }
    while (--argc) {
        std::string cur(*(++argv)); 
        /* Sanitize optimization level for lto */
        if (maybe_linking && (cur == "-Os"|| cur == "-Oz"))
            params.push_back("-O2");
        else 
            params.push_back(cur);
    }
    std::cout << "Maybe Linking? " << maybe_linking << '\n';

    char** cc_params = new char*[params.size() + 2];

    if (argv0.find("heap-expo-clang++") != std::string::npos) {
        char* alt_cxx = getenv("HEAP_EXPO_CXX");
        cc_params[0] = alt_cxx ? alt_cxx : (char*)"clang++-7";
    } else {
        char* alt_cc = getenv("HEAP_EXPO_CC");
        cc_params[0] = alt_cc ? alt_cc : (char*)"clang-7";
    }

    for (int i = 0; i < params.size(); i++) {
        cc_params[i+1] = (char*)params[i].c_str();
    }

    cc_params[params.size()+1] = NULL;

    char** tmp = cc_params;
    while(tmp != NULL && *tmp != NULL) {
        printf("%s ", *tmp);
        tmp++;
    }
    printf("\n");

    execvp(cc_params[0], cc_params);

    std::cerr << "Oops, faild to execute " << std::string(cc_params[0]) << 
        " - check your PATH\n";
    return 0;

}
