#ifndef _VIC_H
#define _VIC_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define VIC_SECTOR_SIZE 512

typedef enum _vic_result
{
    VIC_OK,
    VIC_FAILED,
    VIC_BAD_VERSION,
    VIC_UNEXPECTED,
    VIC_BAD_PARAMETER,
    VIC_BAD_DEVICE,
    VIC_OUT_OF_MEMORY,
    VIC_NOT_FOUND,
    VIC_OUT_OF_BOUNDS,
    VIC_KEY_TOO_BIG,
    VIC_DEVICE_COUNT_FAILED,
    VIC_DEVICE_GET_FAILED,
    VIC_DEVICE_PUT_FAILED,
    VIC_DEVICE_TOO_SMALL,
    VIC_HEADER_READ_FAILED,
    VIC_KEY_MATERIAL_READ_FAILED,
    VIC_HEADER_WRITE_FAILED,
    VIC_KEY_MATERIAL_WRITE_FAILED,
    VIC_KEY_LOOKUP_FAILED,
    VIC_PBKDF2_FAILED,
    VIC_ENCRYPT_FAILED,
    VIC_DECRYPT_FAILED,
    VIC_AFMERGE_FAILED,
    VIC_AFSPLIT_FAILED,
    VIC_EOF,
    VIC_UNSUPPORTED,
    VIC_BUFFER_TOO_SMALL,
    VIC_UNKNOWN_KEYSLOT_TYPE,
    VIC_UNKNOWN_KDF_TYPE,
    VIC_DIGEST_NOT_FOUND,
    VIC_ARGON2I_FAILED,
    VIC_ARGON2ID_FAILED,
    VIC_UNSUPPORTED_DIGEST_TYPE,
    VIC_NUM_CPUS_FAILED,
    VIC_OUT_OF_KEYSLOTS,
    VIC_BAD_UUID,
    VIC_LAST_KEYSLOT,
    VIC_UNSUPPORTED_INTEGRITY_JOURNALING,
    VIC_DEVICE_OPEN_FAILED,
    VIC_PATH_TOO_LONG,
    VIC_FAILED_TO_GET_LOOP_DEVICE,
    VIC_UNSUPPORTED_CIPHER,
    VIC_READ_FAILED,
    VIC_WRITE_FAILED,
    VIC_STAT_FAILED,
    VIC_NOT_BLOCK_MULTIPLE,
    VIC_FILE_TOO_SMALL,
    VIC_OPEN_FAILED,
    VIC_SEEK_FAILED,
    VIC_IOCTL_FAILED,
    VIC_BAD_SIGNATURE,
}
vic_result_t;

typedef struct _vic_device vic_device_t;

typedef struct _vic_block
{
    uint8_t buf[VIC_SECTOR_SIZE];
}
vic_block_t;

struct _vic_device
{
    int (*get)(
        vic_device_t* device,
        uint64_t blkno,
        vic_block_t* blocks,
        size_t nblocks);

    int (*put)(
        vic_device_t* device,
        uint64_t blkno,
        const vic_block_t* blocks,
        size_t nblocks);

    size_t (*count)(vic_device_t* device);
};

typedef struct vic_key
{
    /* 512 bits */
    uint8_t buf[64];
}
vic_key_t;

typedef enum vic_luks_version
{
    LUKS_VERSION_1 = 1,
    LUKS_VERSION_2 = 2,
}
vic_luks_version_t;

typedef struct _vic_luks_stat
{
    vic_luks_version_t version;
    size_t payload_offset;
    size_t payload_size;
}
vic_luks_stat_t;

typedef enum vic_integrity
{
    VIC_INTEGRITY_NONE,
    VIC_INTEGRITY_HMAC_AEAD,
    VIC_INTEGRITY_HMAC_SHA256,
    VIC_INTEGRITY_HMAC_SHA512,
    VIC_INTEGRITY_CMAC_AES,
    VIC_INTEGRITY_POLY1305,
}
vic_integrity_t;

const char* vic_result_string(vic_result_t result);

vic_device_t* vic_open_device(const char* path);

int vic_close_device(vic_device_t* device);

const char* vic_get_device_path(vic_device_t* device);

vic_result_t vic_luks_dump(vic_device_t* device);

vic_result_t vic_luks_load_key(
    const char* path,
    vic_key_t* key,
    size_t* key_size);

vic_result_t vic_luks_format(
    vic_device_t* device,
    vic_luks_version_t version,
    const char* uuid,
    const char* hash,
    const vic_key_t* master_key,
    size_t master_key_bytes,
    const char* pwd,
    vic_integrity_t integrity);

vic_result_t vic_luks_recover_master_key(
    vic_device_t* device,
    const char* pwd,
    vic_key_t* master_key,
    size_t* master_key_bytes);

vic_result_t vic_luks_add_key(
    vic_device_t* device,
    const char* pwd,
    const char* new_pwd);

vic_result_t vic_luks_remove_key(
    vic_device_t* device,
    const char* pwd);

vic_result_t vic_luks_change_key(
    vic_device_t* device,
    const char* old_pwd,
    const char* new_pwd);

vic_result_t vic_luks_stat(vic_device_t* device, vic_luks_stat_t* buf);

vic_result_t vic_luks_open(
    const char* path,
    const char* name,
    const vic_key_t* master_key,
    size_t master_key_bytes);

vic_result_t vic_luks_close(const char* name);

vic_result_t vic_verity_dump(const char* hash_dev);

#endif /* _VIC_H */
