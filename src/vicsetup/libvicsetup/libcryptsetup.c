#include <libcryptsetup.h>

int crypt_format(
    struct crypt_device* cd,
    const char* type,
    const char* cipher,
    const char* cipher_mode,
    const char* uuid,
    const char* volume_key,
    size_t volume_key_size,
    void* params);
