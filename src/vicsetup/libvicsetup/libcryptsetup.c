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

struct crypt_device
{
    vic_blockdev_t* vbd;
    char path[PATH_MAX];
    bool readonly;
};

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
    if (vic_blockdev_open(cd->path, VIC_RDONLY, 0, &cd->vbd) != VIC_OK)
    {
        ret = -ENOENT;
        goto done;
    }

    cd->readonly = true;

    *cd_out = cd;
    cd = NULL;

done:

    if (cd)
        crypt_free(cd);

    return ret;
}

static int _reopen_for_write(struct crypt_device* cd)
{
    int ret = 0;

    if (!cd)
        ERAISE(EINVAL);

    if (cd->readonly)
    {
        if (vic_blockdev_close(cd->vbd) != VIC_OK)
            ERAISE(EIO);

        if (vic_blockdev_open(cd->path, VIC_RDWR, 0, &cd->vbd) != VIC_OK)
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
        if (cd->vbd)
            vic_blockdev_close(cd->vbd);

        memset(cd, 0xdd, sizeof(struct crypt_device));
        free(cd);
    }
}

static bool _valid_key_size(size_t key_size)
{
    switch (key_size)
    {
        case 16:
        case 32:
        case 64:
            return true;
        default:
            return false;
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

    if (!cd || !cipher_name || !cipher_mode)
        ERAISE(EINVAL);

    if (!_valid_key_size(volume_key_size))
        ERAISE(EINVAL);

    /* Type defaults to LUKS version 1 */
    if (!type)
        type = CRYPT_LUKS1;

    ECHECK(_reopen_for_write(cd));

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
            cd->vbd,
            cipher_name,
            cipher_mode,
            uuid,
            hash,
            0, /* mk_iterations */
            (const vic_key_t*)volume_key,
            volume_key_size)) != VIC_OK) /* pwd */
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
        const char* pbkdf_type = NULL;
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
                pbkdf_type = p->pbkdf->type;

                if (p->pbkdf->time_ms ||
                    p->pbkdf->max_memory_kb ||
                    p->pbkdf->parallel_threads ||
                    p->pbkdf->flags)
                {
                    ERAISE(ENOTSUP);
                }
            }
        }

        n = snprintf(cipher, sizeof(cipher), "%s-%s", cipher_name, cipher_mode);
        if (n <= 0 || n >= (int)sizeof(cipher))
            ERAISE(EINVAL);

        if ((r = luks2_format(
            cd->vbd,
            label,
            subsystem,
            cipher,
            uuid,
            hash,
            pbkdf_type,
            iterations,
            (const vic_key_t*)volume_key,
            volume_key_size,
            VIC_INTEGRITY_NONE)) != VIC_OK)
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
