#include "rdrand.h"

uint64_t vic_rdrand(void)
{
    uint64_t r;
#if 1
    __asm__ volatile("rdrand %%rax\n\t" "mov %%rax, %0\n\t" : "=m"(r));
#else
    static uint64_t _rand = 0x22a96be5cd554564;
    r = _rand++ * 37;
#endif
    return r;
}
