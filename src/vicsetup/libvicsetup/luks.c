#include "vic.h"

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>

#include "lukscommon.h"
#include "byteorder.h"
#include "luks2.h"
#include "luks1.h"
#include "raise.h"
#include "hexdump.h"
#include "integrity.h"
#include "dm.h"
#include "strings.h"

VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_hdr_t, magic) == 0);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_hdr_t, version) == 6);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_hdr_t, uuid) == 168);
VIC_STATIC_ASSERT(VIC_OFFSETOF(vic_luks_hdr_t, padding2) == 208);
VIC_STATIC_ASSERT(sizeof(vic_luks_hdr_t) == 512);
VIC_STATIC_ASSERT(sizeof(vic_luks_hdr_t) == VIC_SECTOR_SIZE);

/* These fields have common offsets */
VIC_CHECK_FIELD(luks2_hdr_t, luks1_hdr_t, magic);
VIC_CHECK_FIELD(luks2_hdr_t, luks1_hdr_t, version);
VIC_CHECK_FIELD(luks2_hdr_t, luks1_hdr_t, uuid);

static uint8_t _magic_1st[LUKS_MAGIC_SIZE] = LUKS_MAGIC_1ST;

static uint8_t _magic_2nd[LUKS_MAGIC_SIZE] = LUKS_MAGIC_2ND;

int vic_luks_read_hdr(vic_device_t* device, vic_luks_hdr_t* hdr)
{
    int ret = -1;
    vic_block_t block;

    /* Reject null parameters */
    if (!vic_luks_is_valid_device(device) || !hdr)
        goto done;;

    /* Read one blocks to obtain enough bytes for the header */
    if (device->get(device, 0, &block, 1) != 0)
        goto done;;

    VIC_STATIC_ASSERT(sizeof(vic_luks_hdr_t) <= sizeof(block));
    memcpy(hdr, &block, sizeof(vic_luks_hdr_t));

    if (memcmp(hdr->magic, _magic_1st, sizeof(_magic_1st)) != 0 &&
        memcmp(hdr->magic, _magic_2nd, sizeof(_magic_2nd)) != 0)
    {
        goto done;;
    }

    /* Adjust byte order from big-endian to native */
    hdr->version = vic_swap_u16(hdr->version);

    ret = 0;

done:
    return ret;
}

bool vic_luks_is_valid_device(vic_device_t* device)
{
    return device && device->get && device->put && device->count;
}

vic_result_t vic_luks_dump(vic_device_t* device)
{
    vic_result_t result = VIC_UNEXPECTED;
    vic_luks_hdr_t hdr;
    luks1_hdr_t* hdr1 = NULL;
    luks2_hdr_t* hdr2 = NULL;

    if (!vic_luks_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        if (luks1_read_hdr(device, &hdr1) != 0)
            RAISE(VIC_FAILED);

        if (luks1_dump_hdr(hdr1) != 0)
            RAISE(VIC_FAILED);
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        if (luks2_read_hdr(device, &hdr2) != 0)
            RAISE(VIC_FAILED);

        if (luks2_dump_hdr(hdr2) != 0)
            RAISE(VIC_FAILED);

        /* dump integrity header (if any) */
        {
            luks2_ext_hdr_t* ext = (luks2_ext_hdr_t*)hdr2;
            vic_integrity_sb_t sb;
            const uint64_t offset = ext->segments[0].offset;
            vic_result_t r;

            r = vic_read_integrity_sb(device, offset, &sb);

            if (r == VIC_OK)
                vic_dump_integrity_sb(&sb);
            else if (r != VIC_NOT_FOUND)
                RAISE(r);
        }
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

    result = VIC_OK;

done:

    if (hdr1)
        free(hdr1);

    if (hdr2)
        free(hdr2);

    return result;
}

vic_result_t vic_luks_recover_master_key(
    vic_device_t* device,
    const char* pwd,
    vic_key_t* master_key,
    size_t* master_key_bytes)
{
    vic_result_t result = VIC_UNEXPECTED;
    vic_luks_hdr_t hdr;

    if (!vic_luks_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        CHECK(luks1_recover_master_key(
            device,
            pwd,
            master_key,
            master_key_bytes));
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        CHECK(luks2_recover_master_key(
            device,
            pwd,
            master_key,
            master_key_bytes));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

    result = VIC_OK;

done:

    return result;
}

static vic_result_t _split_cipher(
    const char* cipher,
    char cipher_name[LUKS_CIPHER_NAME_SIZE],
    char cipher_mode[LUKS_CIPHER_MODE_SIZE])
{
    vic_result_t result = VIC_UNEXPECTED;
    size_t offset;

    if (!cipher | !cipher_name || !cipher_mode)
        RAISE(VIC_BAD_PARAMETER);

    /* Find the index of the first '-' character */
    {
        const char* p;

        if (!(p = strchr(cipher, '-')))
            RAISE(VIC_BAD_CIPHER);

        offset = p - cipher;

        if (offset >= LUKS_CIPHER_NAME_SIZE)
            RAISE(VIC_BAD_CIPHER);
    }

    vic_strlcpy(cipher_name, cipher, LUKS_CIPHER_NAME_SIZE);
    cipher_name[offset] = '\0';

    vic_strlcpy(cipher_mode, &cipher[offset+1], LUKS_CIPHER_MODE_SIZE);

    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_luks_format(
    vic_device_t* device,
    vic_luks_version_t version,
    const char* cipher,
    const char* keyslot_cipher,
    const char* uuid,
    const char* hash,
    uint64_t mk_iterations,
    uint64_t slot_iterations,
    uint64_t pbkdf_memory,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* pwd,
    uint32_t flags)
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!cipher)
        cipher = LUKS_DEFAULT_CIPHER;

    if (version == LUKS_VERSION_1)
    {
        char cipher_name[LUKS_CIPHER_NAME_SIZE];
        char cipher_mode[LUKS_CIPHER_MODE_SIZE];

        CHECK(_split_cipher(cipher, cipher_name, cipher_mode));

        CHECK(luks1_format(
            device,
            cipher_name,
            cipher_mode,
            uuid,
            hash,
            mk_iterations,
            slot_iterations,
            master_key,
            master_key_bytes,
            pwd,
            flags));
    }
    else if (version == LUKS_VERSION_2)
    {
        CHECK(luks2_format(
            device,
            cipher,
            keyslot_cipher,
            uuid,
            hash,
            mk_iterations,
            slot_iterations,
            pbkdf_memory,
            master_key,
            master_key_bytes,
            pwd,
            flags));
    }
    else
    {
        RAISE(VIC_BAD_VERSION);
    }

    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_luks_add_key(
    vic_device_t* device,
    const char* keyslot_cipher,
    uint64_t slot_iterations,
    uint64_t pbkdf_memory,
    const char* pwd,
    const char* new_pwd)
{
    vic_result_t result = VIC_UNEXPECTED;
    vic_luks_hdr_t hdr;

    if (!vic_luks_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        return luks1_add_key(device, slot_iterations, pwd, new_pwd);
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        return luks2_add_key(device, keyslot_cipher, slot_iterations,
            pbkdf_memory, pwd, new_pwd);
    }
    else
    {
        return VIC_BAD_VERSION;
    }

done:
    return result;
}

vic_result_t vic_luks_remove_key(vic_device_t* device, const char* pwd)
{
    vic_result_t result = VIC_UNEXPECTED;
    vic_luks_hdr_t hdr;

    if (!vic_luks_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        return luks1_remove_key(device, pwd);
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        return luks2_remove_key(device, pwd);
    }
    else
    {
        return VIC_BAD_VERSION;
    }

done:
    return result;
}

vic_result_t vic_luks_change_key(
    vic_device_t* device,
    const char* old_pwd,
    const char* new_pwd)
{
    vic_result_t result = VIC_UNEXPECTED;
    vic_luks_hdr_t hdr;

    if (!vic_luks_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        return luks1_change_key(device, old_pwd, new_pwd);
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        return luks2_change_key(device, old_pwd, new_pwd);
    }
    else
    {
        return VIC_BAD_VERSION;
    }

done:
    return result;
}

vic_result_t vic_luks_load_key(
    const char* path,
    vic_key_t* key,
    size_t* key_size)
{
    vic_result_t result = VIC_UNEXPECTED;
    struct stat st;
    FILE* is = NULL;

    if (!path || !key || !key_size)
        RAISE(VIC_BAD_PARAMETER);

    if (stat(path, &st) != 0)
        RAISE(VIC_FAILED);

    if ((size_t)st.st_size > sizeof(vic_key_t))
        goto done;

    if (!(is = fopen(path, "rb")))
        RAISE(VIC_FAILED);

    if (fread(key, 1, st.st_size, is) != (size_t)st.st_size)
        RAISE(VIC_FAILED);

    *key_size = st.st_size;

    result = VIC_OK;

done:

    if (is)
        fclose(is);

    return result;
}

vic_result_t vic_luks_stat(vic_device_t* device, vic_luks_stat_t* buf)
{
    vic_result_t result = VIC_UNEXPECTED;
    vic_luks_hdr_t hdr;

    if (!vic_luks_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        return luks1_stat(device, buf);
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        return luks2_stat(device, buf);
    }
    else
    {
        return VIC_BAD_VERSION;
    }

done:
    return result;
}

vic_result_t vic_luks_open(
    const char* path,
    const char* name,
    const vic_key_t* master_key,
    size_t master_key_bytes)
{
    vic_result_t result = VIC_UNEXPECTED;
    vic_luks_hdr_t hdr;
    vic_device_t* device = NULL;

    if (!(device = vic_open_device(path)))
        RAISE(VIC_DEVICE_OPEN_FAILED);

    if (!vic_luks_is_valid_device(device))
        RAISE(VIC_BAD_PARAMETER);

    if (vic_luks_read_hdr(device, &hdr) != 0)
        RAISE(VIC_FAILED);

    if (hdr.version == LUKS_VERSION_1)
    {
        return luks1_open(device, path, name, master_key, master_key_bytes);
    }
    else if (hdr.version == LUKS_VERSION_2)
    {
        return luks2_open(device, path, name, master_key, master_key_bytes);
    }
    else
    {
        return VIC_BAD_VERSION;
    }

done:

    if (device)
        vic_close_device(device);

    return result;
}

vic_result_t vic_luks_close(const char* name)
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!name)
        RAISE(VIC_BAD_PARAMETER);

    /* Remove the <name> device */
    CHECK(vic_dm_remove(name));

    /* Remove the <name>_dif device if it exists */
    {
        char name_dif[PATH_MAX];
        char dmpath[PATH_MAX];

        /* Format the name of the integrity device */
        if (snprintf(name_dif, sizeof(name_dif), "%s_dif", name) >= PATH_MAX)
            RAISE(VIC_BUFFER_TOO_SMALL);

        /* Format the name of the integrity device (under /dev/mapper) */
        snprintf(dmpath, sizeof(dmpath), "/dev/mapper/%s", name_dif);

        if (access(dmpath, R_OK) == 0)
            CHECK(vic_dm_remove(name_dif));
    }

    result = VIC_OK;

done:
    return result;
}
