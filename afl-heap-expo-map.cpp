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

uint32_t shm_id;
int32_t  child_pid,
         out_fd,
         bitmap_fd,
         dev_null_fd = -1;
char    *out_dir,
        *of,
        *out_file;
char*    trace_bits;
char     virgin_bits [HE_MAP_SIZE];
char   **use_argv;

static void remove_shm() {

    shmctl(shm_id, IPC_RMID, NULL);
    
}

void setup_shm() {

    char* shm_str;

    memset(virgin_bits, 255, HE_MAP_SIZE);

    shm_id = shmget(IPC_PRIVATE, HE_MAP_SIZE, IPC_CREAT | IPC_EXCL | 0600);

    if (shm_id < 0) exit(1);

    atexit(remove_shm);

    shm_str = alloc_printf("%d", shm_id);

    setenv(HE_SHM_ENV_VAR, shm_str, 1);

	free(shm_str);

    trace_bits = (char*)shmat(shm_id, NULL, 0);	

}

void run_target(char** argv) {

    int status;

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

static inline void has_new_bits () {
    uint64_t* current = (uint64_t*) trace_bits;
    uint64_t* virgin  = (uint64_t*) virgin_bits;
    
    uint32_t i = (HE_MAP_SIZE >> 3);

    while (i--) {
        if (*current)  {
            printf("O");
            if (*current & *virgin) {
                *virgin &= ~*current;
                printf("X");
            }
        }
        current++;
        virgin++;
    }
    printf("\n");
}

void write_bitmap() {
    char* fname;
    int fd;

    fname = alloc_printf("%s/fuzz_bitmap_heap_expo", out_dir);
    fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0600);

    if (fd < 0) exit(1);

    if (write(fd, virgin_bits, HE_MAP_SIZE)) {}

    close(fd);
    free(fname);
}

int main(int argc, char** argv) {
    int opt;
    uint32_t i, cov;
    struct dirent **ep;
    char* queue_dir;
    char* fn;

    while((opt = getopt(argc, argv, "o:")) > 0) 
        
        switch (opt) {
            case 'o':
                if (out_dir) exit(1);
                out_dir = optarg;
                break;
        }

    detect_file_args(argv + optind + 1);

    use_argv = argv + optind;

    fn = alloc_printf("%s/fuzz_bitmap_heap_expo", out_dir);
    if (true || access(fn, F_OK) == -1) {
        
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
                
                printf("file: %s\n", of);

                out_fd = open(of, O_RDONLY | O_EXCL, 0600);

            }

            run_target(use_argv);

            if (!out_file)
                close(out_fd);
            
            has_new_bits();

                
        }
        printf("Dir finished\n");

        write_bitmap();
    } 
    else {
        printf("Use existing bitmap\n");
    }

    bitmap_fd = open(fn, O_RDONLY | O_EXCL, 0600);

    if (bitmap_fd < 0) exit(1);

    free(fn);

    if (read(bitmap_fd, virgin_bits, HE_MAP_SIZE)) {}

    i = 0;
    cov = 0;
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
    while (i < HE_MAP_SIZE) {
        cov += (8 - counts[(uint8_t)virgin_bits[i]]);
        i++;
    }

    printf("Total bits: %d\n", cov);
    printf("Bitmap cov: %.4f%%\n", (double)cov*100/(HE_MAP_SIZE*8));



    
}
