#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "afl-include.h"

uint32_t shm_id,
         he_shm_id;
int32_t  child_pid,
         out_fd,
         bitmap_fd,
         he_bitmap_fd,
         dev_null_fd = -1;
char    *out_dir,
        *of,
        *out_file;
char    *he_trace_bits,
        *trace_bits;
char     he_virgin_bits [HE_MAP_SIZE],
         virgin_bits [MAP_SIZE];
char   **use_argv;

static void remove_shm() {

    shmctl(he_shm_id, IPC_RMID, NULL);
    shmctl(shm_id, IPC_RMID, NULL);
    
}

void setup_shm() {

    char* he_shm_str;
    char* shm_str;

    atexit(remove_shm);

    memset(he_virgin_bits, 255, HE_MAP_SIZE);

    he_shm_id = shmget(IPC_PRIVATE, HE_MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    if (he_shm_id < 0) exit(1);

    he_shm_str = alloc_printf("%d", he_shm_id);

    setenv(HE_SHM_ENV_VAR, he_shm_str, 1);

	free(he_shm_str);
    
    memset(virgin_bits, 255, MAP_SIZE);

    shm_id = shmget(IPC_PRIVATE, MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    if (shm_id < 0) exit(1);

    shm_str = alloc_printf("%d", shm_id);

    setenv(SHM_ENV_VAR, shm_str, 1);

    free(shm_str);

    he_trace_bits = (char*)shmat(he_shm_id, NULL, 0);	
    trace_bits = (char*)shmat(shm_id, NULL, 0);	

}

void run_target(char** argv) {

    int status;

    memset(he_trace_bits, 0, HE_MAP_SIZE);
    
    memset(trace_bits, 0, HE_MAP_SIZE);
    
    MEM_BARRIER();

    child_pid = fork();

    if (child_pid < 0) exit(1);

    if (!child_pid) {

        setsid();

        if (out_file) {
            dup2(dev_null_fd, 0);
        } else {
            dup2(out_fd, 0);
            close(out_fd);
        }
        
        dup2(dev_null_fd, 1);
        dup2(dev_null_fd, 2);

        close(dev_null_fd);

        execv(argv[0], argv);
        exit(0);

    }

    if (waitpid(child_pid, &status, 0) <= 0) exit(1);

	MEM_BARRIER();
    
}

/* Detect @@ in args. */

void detect_file_args(char** argv) {

  uint32_t i = 0;
  char* cwd = getcwd(NULL, 0);

  if (!cwd) exit(1);

  while (argv[i]) {

    char* aa_loc = strstr(argv[i], "@@");

    if (aa_loc) {

      char *aa_subst, *n_arg;

      /* If we don't have a file name chosen yet, use a safe default. */

      if (!out_file)
        out_file = alloc_printf("%s/.cur_input", out_dir);

      /* Be sure that we're always using fully-qualified paths. */

      if (out_file[0] == '/') aa_subst = out_file;
      else aa_subst = alloc_printf("%s/%s", cwd, out_file);

      /* Construct a replacement argv value. */ 
      *aa_loc = 0;
      n_arg = alloc_printf("%s%s%s", argv[i], aa_subst, aa_loc + 2);
      argv[i] = n_arg;
      *aa_loc = '@';

      if (out_file[0] != '/') free(aa_subst);

    }

    i++;

  }

  free(cwd); /* not tracked */

}

static inline int has_new_bits (char* t, char* v, size_t size) {
    uint64_t* current = (uint64_t*) t;
    uint64_t* virgin  = (uint64_t*) v;
    
    uint32_t i = (size >> 3);
    
    int res = 0;

    while (i--) {
        if (*current)  {
            //printf("O");
            if (*current & *virgin) {
                *virgin &= ~*current;
                //printf("X");
                res = 1;
            }
        }
        current++;
        virgin++;
    }
    //printf("\n");
    return res;
}

void write_bitmap() {
    char* fname;
    int fd;

    fname = alloc_printf("%s/fuzz_bitmap_heap_expo.data", out_dir);
    fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) exit(1);

    if (write(fd, he_virgin_bits, HE_MAP_SIZE)) {}

    close(fd);
    free(fname);

    fname = alloc_printf("%s/fuzz_bitmap.data", out_dir);
    fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) exit(1);

    if (write(fd, virgin_bits, MAP_SIZE)) {}

    close(fd);
    free(fname);
}

int main(int argc, char** argv) {
    int opt;
    uint32_t i, cov1, cov2;
    struct dirent **ep;
    char* queue_dir;
    char* fn1, *fn2;
    int total_case = 0;
    int cov_case = 0;
    int alloc_case = 0;
    int both_case = 0;

    while((opt = getopt(argc, argv, "o:")) > 0) 
        
        switch (opt) {
            case 'o':
                if (out_dir) exit(1);
                out_dir = optarg;
                break;
        }

    detect_file_args(argv + optind + 1);

    use_argv = argv + optind;

    fn1 = alloc_printf("%s/fuzz_bitmap_heap_expo.data", out_dir);
    fn2 = alloc_printf("%s/fuzz_bitmap.data", out_dir);
    if (access(fn1, F_OK) == -1 || access(fn2, F_OK)) {
        
        queue_dir = alloc_printf("%s/queue", out_dir);

        setup_shm();

        dev_null_fd = open("/dev/null", O_RDWR);

        int n = scandir(queue_dir, &ep, 0, alphasort);

        if (n < 0)
            exit(1);

        for (int i = 0; i < n; i++) {

            if (!strcmp(ep[i]->d_name, "..") || !strcmp(ep[i]->d_name, ".") ||
                    !strcmp(ep[i]->d_name, ".state")) continue;

            if (!out_file) {

                of = alloc_printf("%s/%s", queue_dir, ep[i]->d_name);
                
                //printf("file: %s\n", of);

                out_fd = open(of, O_RDONLY | O_EXCL, 0600);

            }

            run_target(use_argv);

            if (!out_file)
                close(out_fd);
            
            int res1 = has_new_bits(he_trace_bits, he_virgin_bits, HE_MAP_SIZE);
            int res2 = has_new_bits(trace_bits, virgin_bits, MAP_SIZE);
            total_case ++;
            if (res1) alloc_case ++;
            if (res2) cov_case ++;
            if (res1 && res2) both_case++;

            if (res1 > res2) printf("X\n");

                
        }
        //printf("Dir finished\n");

        write_bitmap();
    } 
    else {
        printf("Use existing bitmap\n");
    }

    he_bitmap_fd = open(fn1, O_RDONLY | O_EXCL, 0600);

    if (he_bitmap_fd < 0) exit(1);

    free(fn1);

    bitmap_fd = open(fn2, O_RDONLY | O_EXCL, 0600);

    if (bitmap_fd < 0) exit(1);

    free(fn2);
    

    if (read(he_bitmap_fd, he_virgin_bits, HE_MAP_SIZE)) {}

    if (read(bitmap_fd, virgin_bits, MAP_SIZE)) {}

    static uint8_t  counts[] = { 0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3,
            4, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 1, 2, 2, 3, 2,
            3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4,
            5, 4, 5, 5, 6, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2,
            3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4,
            5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5,
            6, 6, 7, 1, 2, 2, 3, 2, 3, 3, 4, 2, 3, 3, 4, 3, 4, 4, 5, 2, 3, 3,
            4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 2, 3, 3, 4, 3, 4, 4, 5, 3,
            4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5, 6, 5, 6, 6,
            7, 2, 3, 3, 4, 3, 4, 4, 5, 3, 4, 4, 5, 4, 5, 5, 6, 3, 4, 4, 5, 4,
            5, 5, 6, 4, 5, 5, 6, 5, 6, 6, 7, 3, 4, 4, 5, 4, 5, 5, 6, 4, 5, 5,
            6, 5, 6, 6, 7, 4, 5, 5, 6, 5, 6, 6, 7, 5, 6, 6, 7, 6, 7, 7, 8 };
    for (i = 0, cov1 = 0; i < HE_MAP_SIZE; i++) {
        cov1 += (8 - counts[(uint8_t)he_virgin_bits[i]]);
    }
    
    for (i = 0, cov2 = 0; i < MAP_SIZE; i++) {
        if ((uint8_t)virgin_bits[i] != 255)
            cov2 ++;
    }

    printf("AFL Total bits: %d\n", cov2);
    printf("AFL Bitmap cov: %.4f%%\n", (double)cov2*100/MAP_SIZE);

    printf("HeapExop Total bits: %d\n", cov1);
    printf("HeapExpo Bitmap cov: %.4f%%\n", (double)cov1*100/(HE_MAP_SIZE*8));

    printf("total: %d, new cov: %d, new alloc: %d, both: %d\n",
            total_case, cov_case, alloc_case, both_case);




    
}
