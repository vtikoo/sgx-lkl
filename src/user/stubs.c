#include "userargs.h"
#include <sys/syscall.h>

sgxlkl_userargs_t* __sgxlkl_userargs;

void sgxlkl_warn(const char* fmt, ...);

int snprintf(char *str, size_t size, const char *format, ...);

/*
**==============================================================================
**
** syscall:
**
**==============================================================================
*/

long lkl_syscall(long no, long* params)
{
    long ret = __sgxlkl_userargs->ua_lkl_syscall(no, params);

    return ret;
}

/*
**==============================================================================
**
** bypasses:
**
**==============================================================================
*/

void sgxlkl_warn(const char* msg, ...)
{
    /* ATTN: ignore variadic arguments */
    return __sgxlkl_userargs->ua_sgxlkl_warn(msg);
}

void sgxlkl_error(const char* msg, ...)
{
    /* ATTN: ignore variadic arguments */
    return __sgxlkl_userargs->ua_sgxlkl_error(msg);
}

void sgxlkl_fail(const char* msg, ...)
{
    /* ATTN: ignore variadic arguments */
    return __sgxlkl_userargs->ua_sgxlkl_fail(msg);
}

bool sgxlkl_in_sw_debug_mode()
{
    return __sgxlkl_userargs->sw_debug_mode;
}

struct lthread* lthread_current()
{
    return __sgxlkl_userargs->ua_lthread_current();
}

int enclave_mmap_flags_supported(int flags, int fd)
{
    return __sgxlkl_userargs->ua_enclave_mmap_flags_supported(flags, fd);
}

void* syscall_SYS_mmap(
    void* addr,
    size_t length,
    int prot,
    int flags,
    int fd,
    off_t offset)
{
    return __sgxlkl_userargs->ua_syscall_SYS_mmap(addr, length, prot, flags,
        fd, offset);
}

void* syscall_SYS_mremap(
    void* old_address,
    size_t old_size,
    size_t new_size,
    int flags,
    void* new_address)
{
    return __sgxlkl_userargs->ua_syscall_SYS_mremap(old_address, old_size,
        new_size, flags, new_address);
}

int syscall_SYS_munmap(void* addr, size_t length)
{
    return __sgxlkl_userargs->ua_syscall_SYS_munmap(addr, length);
}

int syscall_SYS_msync(void* addr, size_t length, int flags)
{
    return __sgxlkl_userargs->ua_syscall_SYS_msync(addr, length, flags);
}

void* enclave_mmap(
    void* addr,
    size_t length,
    int mmap_fixed,
    int prot,
    int zero_pages)
{
    return __sgxlkl_userargs->ua_enclave_mmap(addr, length, mmap_fixed,
        prot, zero_pages);
}

typedef enum
{
    OE_OK,
    OE_FAILURE,
}
oe_result_t;

oe_result_t sgxlkl_host_syscall_mprotect(
    int* retval, void* addr, size_t len, int prot)
{
    return __sgxlkl_userargs->ua_sgxlkl_host_syscall_mprotect(
        retval, addr, len, prot);
}

/*
**==============================================================================
**
** weak form of main (will be overriden by app main)
**
**==============================================================================
*/

__attribute__((weak))
void main()
{
}

/*
**==============================================================================
**
** undefined builtins:
**
**==============================================================================
*/

#pragma GCC diagnostic ignored "-Wbuiltin-declaration-mismatch"

void __muldc3()
{
}

void __mulsc3()
{
}

void __mulxc3()
{
}
