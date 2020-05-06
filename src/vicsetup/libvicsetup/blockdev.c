#include <vic.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <linux/fs.h>
#include "strings.h"
#include "raise.h"

#define DEFAULT_BLOCK_SIZE 512

#define MAGIC 0x0123456789ABCDEF

typedef struct _blockdev
{
    vic_blockdev_t base;
    uint64_t magic;
    char path[PATH_MAX];
    size_t block_size;
    int fd;
}
blockdev_t;

static bool _is_power_of_two(size_t x)
{
    for (size_t i = 0; i < sizeof(size_t) * 8; i++)
    {
        if (x == ((size_t)1 << i))
            return true;
    }

    return false;
}

static bool _valid_blockdev(const blockdev_t* dev)
{
    return dev && dev->magic == MAGIC;
}

static vic_result_t _bd_get_path(
    const vic_blockdev_t* dev_,
    char path[PATH_MAX])
{
    vic_result_t result = VIC_UNEXPECTED;
    const blockdev_t* dev = (const blockdev_t*)dev_;

    if (!_valid_blockdev(dev))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!path)
        RAISE(VIC_BAD_PARAMETER);

    vic_strlcpy(path, dev->path, PATH_MAX);

    result = VIC_OK;

done:
    return result;
}

static vic_result_t _bd_get_block_size(
    const vic_blockdev_t* dev_,
    size_t* block_size)
{
    vic_result_t result = VIC_UNEXPECTED;
    const blockdev_t* dev = (const blockdev_t*)dev_;

    if (!_valid_blockdev(dev))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!block_size)
        RAISE(VIC_BAD_PARAMETER);

    *block_size = dev->block_size;
    result = VIC_OK;

done:
    return result;
}

static vic_result_t _bd_set_block_size(
    vic_blockdev_t* dev_,
    size_t block_size)
{
    vic_result_t result = VIC_UNEXPECTED;
    blockdev_t* dev = (blockdev_t*)dev_;

    if (!_valid_blockdev(dev))
        RAISE(VIC_BAD_PARAMETER);

    if (!block_size || !_is_power_of_two(block_size))
        RAISE(VIC_BAD_PARAMETER);

    dev->block_size = block_size;
    result = VIC_OK;

done:
    return result;
}

static vic_result_t _bd_get_byte_size(
    const vic_blockdev_t* dev_,
    size_t* byte_size)
{
    vic_result_t result = VIC_UNEXPECTED;
    const blockdev_t* dev = (const blockdev_t*)dev_;
    struct stat st;

    if (!_valid_blockdev(dev))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!byte_size)
        RAISE(VIC_BAD_PARAMETER);

    if (fstat(dev->fd, &st) != 0)
        RAISE(VIC_STAT_FAILED);

    if (S_ISREG(st.st_mode))
        *byte_size = st.st_size;
    else if (ioctl(dev->fd, BLKGETSIZE64, byte_size) != 0)
        RAISE(VIC_IOCTL_FAILED);

    result = VIC_OK;

done:

    return result;
}

static vic_result_t _bd_get_num_blocks(
    const vic_blockdev_t* dev_,
    size_t* num_blocks)
{
    vic_result_t result = VIC_UNEXPECTED;
    const blockdev_t* dev = (const blockdev_t*)dev_;
    size_t byte_size;
    size_t block_size;

    if (!_valid_blockdev(dev))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!num_blocks)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(vic_blockdev_get_byte_size(dev_, &byte_size));
    CHECK(vic_blockdev_get_block_size(dev_, &block_size));

    *num_blocks = byte_size / block_size;

    result = VIC_OK;

done:

    return result;
}

static vic_result_t _bd_get(
    vic_blockdev_t* dev_,
    uint64_t blkno,
    void* blocks,
    size_t nblocks)
{
    vic_result_t result = VIC_UNEXPECTED;
    blockdev_t* dev = (blockdev_t*)dev_;
    off_t off;
    size_t size;

    if (!_valid_blockdev(dev))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!blocks)
        RAISE(VIC_BAD_PARAMETER);

    off = blkno * dev->block_size;

    if (lseek(dev->fd, off, SEEK_SET) != off)
        RAISE(VIC_SEEK_FAILED);

    size = nblocks * dev->block_size;

    if (read(dev->fd, blocks, size) != (ssize_t)size)
        RAISE(VIC_READ_FAILED);

    result = VIC_OK;

done:
    return result;
}

static vic_result_t _bd_put(
    vic_blockdev_t* dev_,
    uint64_t blkno,
    const void* blocks,
    size_t nblocks)
{
    vic_result_t result = VIC_UNEXPECTED;
    blockdev_t* dev = (blockdev_t*)dev_;
    off_t off;
    size_t size;

    if (!_valid_blockdev(dev))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    if (!blocks)
        RAISE(VIC_BAD_PARAMETER);

    off = blkno * dev->block_size;

    if (lseek(dev->fd, off, SEEK_SET) != off)
        RAISE(VIC_SEEK_FAILED);

    size = nblocks * dev->block_size;

    if (write(dev->fd, blocks, size) != (ssize_t)size)
        RAISE(VIC_READ_FAILED);

    result = VIC_OK;

done:
    return result;
}

static vic_result_t _bd_close(vic_blockdev_t* dev_)
{
    vic_result_t result = VIC_UNEXPECTED;
    blockdev_t* dev = (blockdev_t*)dev_;

    if (!_valid_blockdev(dev))
        RAISE(VIC_BAD_BLOCK_DEVICE);

    close(dev->fd);
    memset(dev, 0, sizeof(blockdev_t));
    free(dev);

    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_blockdev_open(
    const char* path,
    uint32_t flags,
    size_t block_size,
    vic_blockdev_t** dev_out)
{
    vic_result_t result = VIC_UNEXPECTED;
    blockdev_t* dev = NULL;
    int open_flags = 0;
    int mode = 0;

    /* Resolve the open() flags and mode */
    {
        if (flags & VIC_RDWR)
        {
            if ((flags & VIC_RDONLY) || ((flags & VIC_WRONLY)))
                RAISE(VIC_BAD_FLAGS);

            open_flags |= O_RDWR;
        }

        if (flags & VIC_RDONLY)
        {
            if ((flags & VIC_RDWR) || ((flags & VIC_WRONLY)))
                RAISE(VIC_BAD_FLAGS);

            open_flags |= O_RDONLY;
        }

        if (flags & VIC_WRONLY)
        {
            if ((flags & VIC_RDWR) || ((flags & VIC_RDONLY)))
                RAISE(VIC_BAD_FLAGS);

            open_flags |= O_WRONLY;
        }

        if (flags & VIC_CREATE)
        {
            open_flags |= O_CREAT;
            mode = 0600;
        }

        if (flags & VIC_TRUNC)
            open_flags |= O_TRUNC;
    }

    if (block_size == 0)
        block_size = DEFAULT_BLOCK_SIZE;

    if (!path || !_is_power_of_two(block_size) || !dev_out)
        RAISE(VIC_BAD_PARAMETER);

    if (!(dev = calloc(1, sizeof(blockdev_t))))
        RAISE(VIC_OUT_OF_MEMORY);

    dev->magic = MAGIC;

    if (vic_strlcpy(dev->path, path, PATH_MAX) >= PATH_MAX)
        RAISE(VIC_UNEXPECTED);

    if ((dev->fd = open(path, open_flags, mode)) < 0)
        RAISE(VIC_OPEN_FAILED);

    dev->base.bd_get_path = _bd_get_path;
    dev->base.bd_get = _bd_get;
    dev->base.bd_put = _bd_put;
    dev->base.bd_get_byte_size = _bd_get_byte_size;
    dev->base.bd_get_num_blocks = _bd_get_num_blocks;
    dev->base.bd_get_block_size = _bd_get_block_size;
    dev->base.bd_set_block_size = _bd_set_block_size;
    dev->base.bd_close = _bd_close;
    dev->block_size = block_size;

    /* Check that the device size is a multiple of the block size */
    {
        size_t byte_size;

        CHECK(vic_blockdev_get_byte_size(&dev->base, &byte_size));

        if (byte_size % block_size)
            RAISE(VIC_NOT_BLOCK_MULTIPLE);
    }

    *dev_out = &dev->base;
    dev = NULL;
    result = VIC_OK;

done:

    if (dev)
        free(dev);

    return result;
}

vic_result_t vic_blockdev_get_path(
    const vic_blockdev_t* dev,
    char path[PATH_MAX])
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!dev)
        RAISE(result);

    CHECK(dev->bd_get_path(dev, path));
    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_blockdev_get_block_size(
    const vic_blockdev_t* dev,
    size_t* block_size)
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!dev)
        RAISE(result);

    CHECK(dev->bd_get_block_size(dev, block_size));
    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_blockdev_set_block_size(
    vic_blockdev_t* dev,
    size_t block_size)
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!dev)
        RAISE(result);

    CHECK(dev->bd_set_block_size(dev, block_size));
    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_blockdev_get_byte_size(
    const vic_blockdev_t* dev,
    size_t* byte_size)
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!dev)
        RAISE(result);

    CHECK(dev->bd_get_byte_size(dev, byte_size));
    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_blockdev_get_num_blocks(
    vic_blockdev_t* dev,
    size_t* num_blocks)
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!dev)
        RAISE(result);

    CHECK(dev->bd_get_num_blocks(dev, num_blocks));
    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_blockdev_get(
    vic_blockdev_t* dev,
    uint64_t blkno,
    void* blocks,
    size_t nblocks)
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!dev)
        RAISE(result);

    CHECK(dev->bd_get(dev, blkno, blocks, nblocks));
    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_blockdev_put(
    vic_blockdev_t* dev,
    uint64_t blkno,
    const void* blocks,
    size_t nblocks)
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!dev)
        RAISE(result);

    CHECK(dev->bd_put(dev, blkno, blocks, nblocks));
    result = VIC_OK;

done:
    return result;
}

vic_result_t vic_blockdev_close(vic_blockdev_t* dev)
{
    vic_result_t result = VIC_UNEXPECTED;

    if (!dev)
        RAISE(result);

    CHECK(dev->bd_close(dev));
    result = VIC_OK;

done:
    return result;
}
