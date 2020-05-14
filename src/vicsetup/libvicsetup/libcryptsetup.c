#include <libcryptsetup.h>
#include <vic.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "eraise.h"
#include "luks1.h"
#include "luks2.h"
#include "integrity.h"
#include "strings.h"
#include "crypto.h"

#define MAGIC 0xa8ea23c6

struct crypt_device
{
    char type[16];
    uint32_t magic;
    vic_blockdev_t* bd;
    char path[PATH_MAX];
    bool readonly;

    struct
    {
        vic_key_t volume_key;
        size_t volume_key_size;
        char cipher[LUKS2_ENCRYPTION_SIZE];

        struct crypt_pbkdf_type pbkdf;
        char pbkdf_type_buf[32];
        char pbkdf_hash_buf[VIC_MAX_HASH_SIZE];
    }
    luks2_format;

    struct
    {
        luks1_hdr_t* hdr;
    }
    luks1_load;

    struct
    {
        luks2_hdr_t* hdr;
    }
    luks2_load;

    struct
    {
        vic_verity_sb_t sb;
    }
    verity_load;
};

static int _set_pbkdf_type(
    struct crypt_device* cd,
    const struct crypt_pbkdf_type* pbkdf)
{
    int ret = 0;

    if (!cd || !pbkdf)
        ERAISE(EINVAL);

    cd->luks2_format.pbkdf = *pbkdf;

    if (pbkdf->type)
    {
        const size_t n = sizeof(cd->luks2_format.pbkdf_type_buf);

        if (vic_strlcpy(cd->luks2_format.pbkdf_type_buf, pbkdf->type, n) >= n)
            ERAISE(EINVAL);

        cd->luks2_format.pbkdf.type = cd->luks2_format.pbkdf_type_buf;
    }

    if (pbkdf->hash)
    {
        const size_t n = sizeof(cd->luks2_format.pbkdf_hash_buf);

        if (vic_strlcpy(cd->luks2_format.pbkdf_hash_buf, pbkdf->hash, n) >= n)
            ERAISE(EINVAL);

        cd->luks2_format.pbkdf.hash = cd->luks2_format.pbkdf_hash_buf;
    }

done:
    return ret;
}

static bool _valid_cd(const struct crypt_device* cd)
{
    return cd && cd->magic == MAGIC;
}

static bool _valid_type(const char* type)
{
    return
        strcmp(type, CRYPT_LUKS1) == 0 ||
        strcmp(type, CRYPT_LUKS2) == 0 ||
        strcmp(type, CRYPT_VERITY) == 0 ||
        strcmp(type, CRYPT_INTEGRITY) == 0;
}

int crypt_init(struct crypt_device** cd_out, const char* device)
{
    int ret = 0;
    struct crypt_device* cd = NULL;

    if (!cd_out || !device || strlen(device) >= PATH_MAX)
    {
        ret = -EINVAL;
        goto done;
    }

    if (!(cd = calloc(sizeof(struct crypt_device), 1)))
    {
        ret = -ENOMEM;
        goto done;
    }

    strcpy(cd->path, device);

    /* Open device initially for read only */
    if (vic_blockdev_open(cd->path, VIC_RDONLY, 0, &cd->bd) != VIC_OK)
    {
        ret = -ENOENT;
        goto done;
    }

    cd->readonly = true;
    cd->magic = MAGIC;
    *cd_out = cd;
    cd = NULL;

done:

    if (cd)
        crypt_free(cd);

    return ret;
}

static int _force_open_for_write(struct crypt_device* cd)
{
    int ret = 0;

    if (!cd)
        ERAISE(EINVAL);

    if (cd->readonly)
    {
        if (vic_blockdev_close(cd->bd) != VIC_OK)
            ERAISE(EIO);

        if (vic_blockdev_open(cd->path, VIC_RDWR, 0, &cd->bd) != VIC_OK)
            ERAISE(EIO);

        cd->readonly = false;
    }

done:
    return ret;
}

void crypt_free(struct crypt_device* cd)
{
    if (cd)
    {
        if (cd->bd)
            vic_blockdev_close(cd->bd);

        if (strcmp(cd->type, CRYPT_LUKS1) == 0)
        {
            free(cd->luks1_load.hdr);
        }
        else if (strcmp(cd->type, CRYPT_LUKS2) == 0)
        {
            free(cd->luks2_load.hdr);
        }

        memset(cd, 0, sizeof(struct crypt_device));
        free(cd);
    }
}

int crypt_format(
    struct crypt_device* cd,
    const char* type,
    const char* cipher_name,
    const char* cipher_mode,
    const char* uuid,
    const char* volume_key,
    size_t volume_key_size,
    void* params)
{
    int ret = 0;

    if (!type)
        type = CRYPT_LUKS1;

    if (!_valid_cd(cd) || !_valid_type(type) || !cipher_name || !cipher_mode)
        ERAISE(EINVAL);

    if (!volume_key_size || volume_key_size > sizeof(vic_key_t))
        ERAISE(EINVAL);

    /* Cache the key or generated key (for use in subsequent functions) */
    if (volume_key)
    {
        cd->luks2_format.volume_key_size = volume_key_size;
        memcpy(&cd->luks2_format.volume_key, volume_key, volume_key_size);
    }
    else
    {
        /* Save in crypt device for later (used when adding keyslots) */
        vic_luks_random(&cd->luks2_format.volume_key, volume_key_size);
        cd->luks2_format.volume_key_size = volume_key_size;
        volume_key = (const char*)cd->luks2_format.volume_key.buf;
    }

    ECHECK(_force_open_for_write(cd));

    /* Save the type for use in subsequent calls */
    vic_strlcpy(cd->type, type, sizeof(cd->type));

    if (strcmp(type, CRYPT_LUKS1) == 0)
    {
        struct crypt_params_luks1* p = params;
        const char* hash = NULL;
        vic_result_t r;

        if (p)
        {
            if (p->data_alignment || p->data_device)
                ERAISE(ENOTSUP);

            hash = p->hash;
        }

        if ((r = luks1_format(
            cd->bd,
            cipher_name,
            cipher_mode,
            uuid,
            hash,
            0, /* mk_iterations */
            (const vic_key_t*)volume_key,
            volume_key_size)) != VIC_OK)
        {
            ERAISE(EINVAL);
        }
    }
    else if (strcmp(type, CRYPT_LUKS2) == 0)
    {
        char cipher[128];
        const struct crypt_params_luks2* p = params;
        const char* hash = NULL;
        const char* label = NULL;
        const char* subsystem = NULL;
        uint64_t iterations = 0;
        vic_integrity_t integrity = VIC_INTEGRITY_NONE;
        vic_result_t r;
        int n;

        if (p)
        {
            /* ATTN: sector_size not supported */
            if (p->integrity_params ||
                p->data_alignment ||
                p->data_device ||
                (p->sector_size && p->sector_size != VIC_SECTOR_SIZE))
            {
                ERAISE(ENOTSUP);
            }

            label = p->label;
            subsystem = p->subsystem;

            if (p->integrity)
            {
                if ((integrity = vic_integrity_enum(
                    p->integrity)) == VIC_INTEGRITY_NONE)
                {
                    ERAISE(EINVAL);
                }
            }

            if (p->pbkdf)
            {
                hash = p->pbkdf->hash;
                iterations = p->pbkdf->iterations;

                /* Save pbkdf for use in subsequent functions */
                ECHECK(_set_pbkdf_type(cd, p->pbkdf));
            }
        }

        n = snprintf(cipher, sizeof(cipher), "%s-%s", cipher_name, cipher_mode);
        if (n <= 0 || n >= (int)sizeof(cipher))
            ERAISE(EINVAL);

        /* Save the cipher for later (used when adding keyslots) */
        vic_strlcpy(cd->luks2_format.cipher, cipher, sizeof(cd->luks2_format.cipher));

        if ((r = luks2_format(
            cd->bd,
            label,
            subsystem,
            cipher,
            uuid,
            hash,
            iterations,
            (const vic_key_t*)volume_key,
            volume_key_size,
            integrity)) != VIC_OK)
        {
            ERAISE(EINVAL);
        }
    }
    else
    {
        ERAISE(EINVAL);
    }

done:
    return ret;
}

int crypt_keyslot_add_by_key(
    struct crypt_device* cd,
    int keyslot,
    const char* volume_key,
    size_t volume_key_size,
    const char* passphrase,
    size_t passphrase_size,
    uint32_t flags)
{
    int ret = 0;

    /* Check parameters */
    {
        if (!_valid_cd(cd))
            ERAISE(EINVAL);

        /* ATTN: keyslot selection not supported */
        if (keyslot != CRYPT_ANY_SLOT)
            ERAISE(ENOTSUP);

        /* If volume_key is null, use the one stored by crypt_format() */
        if (!volume_key)
        {
            if (volume_key_size != 0)
                ERAISE(EINVAL);

            volume_key = (const char*)cd->luks2_format.volume_key.buf;
            volume_key_size = cd->luks2_format.volume_key_size;
        }

        if (volume_key_size && !volume_key_size)
            ERAISE(EINVAL);

        if (!passphrase || !passphrase_size)
            ERAISE(EINVAL);

        /* ATTN: limited flag support */
        if (flags != CRYPT_PBKDF_NO_BENCHMARK && flags != 0)
            ERAISE(EINVAL);

        if (!_valid_type(cd->type))
            ERAISE(EINVAL);
    }

    /* Add the keyslot */
    if (strcmp(cd->type, CRYPT_LUKS1) == 0)
    {
        vic_result_t r;

        if ((r = luks1_add_key_by_master_key(
            cd->bd,
            0,
            (const vic_key_t*)volume_key,
            volume_key_size,
            passphrase,
            passphrase_size)) != VIC_OK)
        {
            ERAISE(EINVAL);
        }
    }
    else if (strcmp(cd->type, CRYPT_LUKS2) == 0)
    {
        vic_result_t r;
        vic_kdf_t kdf =
        {
            .hash = cd->luks2_format.pbkdf.hash,
            .iterations = cd->luks2_format.pbkdf.iterations,
            .time = cd->luks2_format.pbkdf.time_ms,
            .memory = cd->luks2_format.pbkdf.max_memory_kb,
            .cpus = cd->luks2_format.pbkdf.parallel_threads,
        };

        if ((r = luks2_add_key_by_master_key(
            cd->bd,
            cd->luks2_format.cipher,
            cd->luks2_format.pbkdf.type,
            &kdf,
            (const vic_key_t*)volume_key,
            volume_key_size,
            passphrase,
            passphrase_size)) != VIC_OK)
        {
            ERAISE(EINVAL);
        }
    }
    else
    {
        ERAISE(EINVAL);
    }

done:
    return ret;
}


int crypt_load(
    struct crypt_device* cd,
    const char* requested_type,
    void* params)
{
    int ret = 0;

    (void)params;

    if (!_valid_cd(cd) || !cd->bd || !requested_type)
        ERAISE(EINVAL);

    if (*cd->type != '\0')
        ERAISE(EBUSY);

    if (strcmp(requested_type, CRYPT_LUKS1) == 0)
    {
        vic_strlcpy(cd->type, requested_type, sizeof(cd->type));

        if (luks1_read_hdr(cd->bd, &cd->luks1_load.hdr) != VIC_OK)
            ERAISE(EIO);
    }
    else if (strcmp(requested_type, CRYPT_LUKS2) == 0)
    {
        vic_strlcpy(cd->type, requested_type, sizeof(cd->type));

        if (luks2_read_hdr(cd->bd, &cd->luks2_load.hdr) != VIC_OK)
            ERAISE(EIO);
    }
    else if (strcmp(requested_type, CRYPT_VERITY) == 0)
    {
        vic_verity_sb_t* sb = &cd->verity_load.sb;
        const size_t expected_block_size = 4096;
        size_t block_size;

        vic_strlcpy(cd->type, requested_type, sizeof(cd->type));

        if (vic_blockdev_set_block_size(cd->bd, expected_block_size) != VIC_OK)
            ERAISE(EINVAL);

        if (vic_verity_read_superblock(cd->bd, sb) != VIC_OK)
            ERAISE(EIO);

        if (sb->data_block_size != expected_block_size)
            ERAISE(ENOTSUP);

        if (sb->hash_block_size != expected_block_size)
            ERAISE(ENOTSUP);

        if (vic_blockdev_get_block_size(cd->bd, &block_size) != VIC_OK)
            ERAISE(EINVAL);

        if (block_size != expected_block_size)
            ERAISE(ENOTSUP);

        /* ATTN: handle params here! */
    }
    else if (strcmp(requested_type, CRYPT_INTEGRITY) == 0)
    {
        ERAISE(ENOTSUP);
    }

done:
    return ret;
}
