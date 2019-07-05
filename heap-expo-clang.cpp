#include <iostream>
#include <vector>
#include <cstring>
#include <unistd.h>

int main(int argc, char** argv) {
    int _argc;
    char *path, *alt_cc, *alt_cxx;
    char **_argv;
    char **cc_params;
    std::string argv0(argv[0]);
    std::string obj_path;
    std::vector<std::string> params;
    bool maybe_linking   = true,
         x_set           = false,
         multi_threading = false;
    int bit_mode = 0;

    if (argc < 2) {
        std::cerr << "\n"
            "This is a helper application for heap exposure. It serves as a drop-in\n"
            "replacement for clang, letting you recompile third-party code with the\n"
            "required runtime instrumentation.\n\n";
        return 1;
    }

    path = getenv("HEAP_EXPO_PATH");

    if (path) 
        obj_path = std::string(path);
    else 
        obj_path = argv0.substr(0, argv0.find_last_of('/'));


    /* Add llvm pass argument */
    params.push_back("-Xclang");
    params.push_back("-load");
    params.push_back("-Xclang");
    params.push_back(obj_path + "/LLVMHeapExpo.so");

    /* Keep frame pointer for unwind */
    params.push_back("-fno-omit-frame-pointer");


    if (argc == 1 && !strcmp(argv[1], "-v")) maybe_linking = false;

    /* Check is linker is involved */
    _argc = argc;
    _argv = argv;
    while (--_argc) {
        std::string cur(*(++_argv));
        
        if (cur == "-c" || cur == "-S" || cur == "-E")
            maybe_linking = false;

        if (cur == "-m32")
            bit_mode = 32;

        if (cur == "-m64")
            bit_mode = 64;
        
        if (cur == "-x")
            x_set = true;

        if (cur == "-pthread" || cur == "-lpthread") 
            multi_threading = true;
    }
    
    /* 
     * Add rt objects if involving linking 
     * This has to go before the src file so that LLVM Pass can see rt functions
     */
    if (maybe_linking) {
#ifdef LTO
        params.push_back("-flto");
#endif
        params.push_back("-lpthread");
        params.push_back("-lunwind");
        params.push_back("-lm");

        if (x_set) {
            params.push_back("-x");
            params.push_back("none");
        }

        std::string suffix;
        if (multi_threading)
            suffix = "-mt.o";
        else
            suffix = ".o";
            
        switch (bit_mode) {
            case 0:
                params.push_back(obj_path + "/heap-expo-rt" + suffix);
                break;

            case 32:
                params.push_back(obj_path + "/heap-expo-rt-32" + suffix);
                if (access(params[params.size()-1].c_str(), R_OK)) {
                    std::cerr << "-m32 is not supported by your compiler\n";
                    return 1;
                }
                break;

            case 64:
                params.push_back(obj_path + "/heap-expo-rt-64" + suffix);
                if (access(params[params.size()-1].c_str(), R_OK)) {
                    std::cerr << "-m64 is not supported by your compiler\n";
                    return 1;
                }
                break;

        }
        /* force c++ because rt will use STL lib */
        params.push_back("-lstdc++"); 
    }

    /* Sanitize and add input arguments */
    _argc = argc;
    _argv = argv;
    while (--_argc) {
        std::string cur(*(++_argv)); 
#ifdef LTO
        /* Sanitize optimization level for lto */
        if (maybe_linking && (cur == "-Os"|| cur == "-Oz"))
            params.push_back("-O2");
        else 
            params.push_back(cur);
#else 
        params.push_back(cur);
#endif
    }

    cc_params = new char*[params.size() + 2];

    /* Choose a clang compiler */
    if (argv0.find("heap-expo-clang++") != std::string::npos) {
        alt_cxx = getenv("HEAP_EXPO_CXX");
        cc_params[0] = alt_cxx ? alt_cxx : (char*)"clang++-7";
    } else {
        alt_cc = getenv("HEAP_EXPO_CC");
        cc_params[0] = alt_cc ? alt_cc : (char*)"clang-7";
    }

    for (int i = 0; i < params.size(); i++) {
        cc_params[i+1] = (char*)params[i].c_str();
    }

    cc_params[params.size()+1] = NULL;

    /*
    char** tmp = cc_params;
    while(tmp != NULL && *tmp != NULL) {
        fprintf(stderr, "%s ", *tmp);
        tmp++;
    }
    fprintf(stderr, "\n");
    */

    execvp(cc_params[0], cc_params);

    std::cerr << "Oops, faild to execute " << std::string(cc_params[0]) << 
        " - check your PATH\n";
    return 0;

}
