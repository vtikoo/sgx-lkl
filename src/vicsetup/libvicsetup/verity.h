#ifndef _VIC_VERITY_H
#define _VIC_VERITY_H

#include <stdint.h>
#include "defs.h"
#include "vic.h"

#define VIC_VERITY_MAX_SALT_SIZE 256

VIC_STATIC_ASSERT(sizeof(vic_verity_sb_t) == 512);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, signature) == 0);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, version) == 8);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, hash_type) == 12);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, uuid) == 16);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, algorithm) == 32);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, data_block_size) == 64);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, hash_block_size) == 68);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, data_blocks) == 72);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, salt_size) == 80);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, _pad1) == 82);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, salt) == 88);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_verity_sb_t, _pad2) == 344);

void vic_verity_dump_sb(vic_verity_sb_t* sb);

#endif /* _VIC_VERITY_H */
