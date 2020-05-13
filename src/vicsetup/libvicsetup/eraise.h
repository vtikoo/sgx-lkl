#ifndef _VIC_ERAISE_H
#define _VIC_ERAISE_H

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "vic.h"

#define TRACE_RAISE

#define ERAISE(ERRNUM)                                   \
    do                                                   \
    {                                                    \
        ret = -ERRNUM;                                   \
        __eraise(__FILE__, __LINE__, __FUNCTION__, ret); \
        fflush(stdout);                                  \
        goto done;                                       \
    }                                                    \
    while (0)

#define ECHECK(ERRNUM)                                       \
    do                                                       \
    {                                                        \
        int _r_ = -ERRNUM;                                   \
        if (_r_ != VIC_OK)                                   \
        {                                                    \
            ret = _r_;                                       \
            __eraise(__FILE__, __LINE__, __FUNCTION__, ret); \
            goto done;                                       \
        }                                                    \
    }                                                        \
    while (0)

static __inline__ void __eraise(
    const char* file,
    uint32_t line,
    const char* func,
    int errnum)
{
#ifdef TRACE_RAISE
    if (errnum < 0)
        errnum = -errnum;
    const char* str = strerror(errnum);
    printf("ERAISE: %s(%u): %s(): %s(%u)\n", file, line, func, str, errnum);
    fflush(stdout);
#endif
}

#endif /* _VIC_ERAISE_H */
