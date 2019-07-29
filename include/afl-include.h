#define MAP_SIZE (1<<16)
#define HE_MAP_SIZE (1<<13)

#define HE_SHM_ENV_VAR "__HEXPO_SHM_ID"
#define SHM_ENV_VAR "__AFL_SHM_ID"

#define MEM_BARRIER() \
    asm volatile("" ::: "memory")

#define alloc_printf(_str...) ({ \
    char* _tmp; \
    int _len = snprintf(NULL, 0, _str); \
    if (_len < 0) exit(1); \
    _tmp = (char*)malloc(_len + 1); \
    snprintf((char*)_tmp, _len + 1, _str); \
    _tmp; \
  })
