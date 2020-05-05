#ifndef _VIC_STRINGS_H
#define _VIC_STRINGS_H

#include "defs.h"
#include <stddef.h>

size_t vic_strlcpy(char* dest, const char* src, size_t size);

size_t vic_strlcat(char* dest, const char* src, size_t size);

#endif /* _VIC_STRINGS_H */
