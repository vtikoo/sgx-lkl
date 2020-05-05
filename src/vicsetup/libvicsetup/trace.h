#ifndef _VIC_TRACE_H
#define _VIC_TRACE_H

#include <stdio.h>

#define VIC_TRACE                                          \
    do                                                      \
    {                                                       \
        printf("VIC_TRACE: %s(%u)\n", __FILE__, __LINE__); \
        fflush(stdout);                                     \
    }                                                       \
    while (0)

#endif /* _VIC_TRACE_H */
