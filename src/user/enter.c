#include "userargs.h"
#include "../../sgx-lkl-musl/src/internal/pthread_impl.h"

_Noreturn void __dls3(void* conf, void* tos);
void __libc_start_init(void);
void sgxlkl_warn(const char* fmt, ...);
void __init_libc(char **envp, char *pn);
void* _dlstart_c(size_t base);

_Noreturn void __dls3(void* conf, void* tos);
void __libc_start_init(void);
void sgxlkl_warn(const char* fmt, ...);
void __init_libc(char **envp, char *pn);
void* _dlstart_c(size_t base);
void init_sysconf(long nproc_conf, long nproc_onln);

static inline void _barrier()
{
    __asm__ __volatile__( "" : : : "memory" );
}

/* forward declaration */
struct dso;

void __attribute__ ((noinline))
__gdb_hook_load_debug_symbols(struct dso *dso, void *symmem, ssize_t symsz)
{
    sgxlkl_warn("********** __gdb_hook_load_debug_symbols(): "
        "dso=%p symmem=%p symsz=%zd\n",
        dso, symmem, symsz);
    __asm__ volatile ("" : : "m" (dso), "m" (symmem), "m" (symsz));
}

void __attribute__ ((noinline))
__gdb_hook_load_debug_symbols_from_file(struct dso *dso, char *libpath)
{
    sgxlkl_warn("********** __gdb_hook_load_debug_symbols_from_file()\n");
    __asm__ volatile ("" : : "m" (dso), "m" (libpath));
}

void __attribute__ ((noinline))
__gdb_hook_load_debug_symbols_wrap(struct dso *dso, void *symmem, ssize_t symsz)
{
    sgxlkl_warn("********** user __gdb_hook_load_debug_symbols_wrap()");
    return __gdb_hook_load_debug_symbols(dso, symmem, symsz);
}

void __attribute__ ((noinline))
__gdb_hook_load_debug_symbols_from_file_wrap(struct dso *dso, char *libpath)
{
    sgxlkl_warn("********** user __gdb_hook_load_debug_symbols_from_file_wrap()");
    return __gdb_hook_load_debug_symbols_from_file(dso, libpath);
}

void sgxlkl_user_enter(sgxlkl_userargs_t* args)
{
    __sgxlkl_userargs = args;

    sgxlkl_warn("********** sgxlkl_user_enter()\n");

    _dlstart_c((size_t)args->elf64_hdr);

    libc.user_tls_enabled = 1;

    init_sysconf(args->num_ethreads, args->num_ethreads);

    init_clock_res((struct timespec*)args->clock_res);

    __init_libc(args->argv + args->argc + 1, args->argv[0]);

    __libc_start_init();
    _barrier();

    pthread_t self = __pthread_self();
    self->locale = &libc.global_locale;

    __dls3(args->stack, __builtin_frame_address(0));
}
