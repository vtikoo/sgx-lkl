#ifndef _VIC_STRINGS_H
#define _VIC_STRINGS_H

#include "defs.h"
#include <stddef.h>

size_t vic_strlcpy(char* dest, const char* src, size_t size);

size_t vic_strlcat(char* dest, const char* src, size_t size);

/* Returns non-zero on overflow */
#define STRLCPY(DEST, SRC) \
    (vic_strlcpy(DEST, SRC, sizeof(DEST)) >= sizeof(DEST))

/* Returns non-zero on overflow */
#define STRLCAT(DEST, SRC) \
    (vic_strlcat(DEST, SRC, sizeof(DEST)) >= sizeof(DEST))

#endif /* _VIC_STRINGS_H */
