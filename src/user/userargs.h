#ifndef _SGXLKL_USER_FUNCTBL_H
#define _SGXLKL_USER_FUNCTBL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef long time_t;

struct sgxlkl_user_timespec
{
    time_t tv_sec;
    long tv_nsec;
};

typedef int64_t off_t;

typedef struct sgxlkl_userargs
{
    /* Functions: ATTN: remove all but lkl_syscall() */
    long (*ua_lkl_syscall)(long no, long* params);
    void (*ua_sgxlkl_warn)(const char* msg, ...);
    void (*ua_sgxlkl_error)(const char* msg, ...);
    void (*ua_sgxlkl_fail)(const char* msg, ...);
    bool (*ua_sgxlkl_in_sw_debug_mode)(void);
    struct lthread* (*ua_lthread_current)(void);
    int (*ua_enclave_mmap_flags_supported)(int flags, int fd);
    void* (*ua_syscall_SYS_mmap)(
        void* addr,
        size_t length,
        int prot,
        int flags,
        int fd,
        off_t offset);
    void* (*ua_syscall_SYS_mremap)(
        void* old_address,
        size_t old_size,
        size_t new_size,
        int flags,
        void* new_address);
    int (*ua_syscall_SYS_munmap)(void* addr, size_t length);
    int (*ua_syscall_SYS_msync)(void* addr, size_t length, int flags);
    void* (*ua_enclave_mmap)(
        void* addr,
        size_t length,
        int mmap_fixed,
        int prot,
        int zero_pages);
    int (*ua_sgxlkl_host_syscall_mprotect)(
        int* retval, void* addr, size_t len, int prot);

    /* Arguments */
    int argc;
    char** argv;
    void* stack;
    const void* elf64_hdr;
    size_t num_ethreads;

    /* to be passed to init_clock_res() */
    struct sgxlkl_user_timespec clock_res[8];
}
sgxlkl_userargs_t;

extern sgxlkl_userargs_t* __sgxlkl_userargs;

#endif /* _SGXLKL_USER_FUNCTBL_H */
