#include <vic.h>

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <limits.h>

#include "strings.h"

#define MAGIC 0xdcfe3914

typedef struct device
{
    vic_device_t base;
    uint64_t magic;
    char path[PATH_MAX];
    int fd;
}
device_t;

static bool _valid_device(device_t* device)
{
    return device && device->magic == MAGIC;
}

static int _get(
    vic_device_t* device_,
    uint64_t blkno,
    vic_block_t* blocks,
    size_t nblocks)
{
    device_t* device = (device_t*)device_;
    off_t off;
    size_t size;

    if (!_valid_device(device))
        return -1;

    off = blkno * sizeof(vic_block_t);

    if (lseek(device->fd, off, SEEK_SET) != off)
        return -1;

    size = nblocks * sizeof(vic_block_t);

    if (read(device->fd, blocks, size) != (ssize_t)size)
        return -1;

    return 0;
}

static int _puts(
    vic_device_t* device_,
    uint64_t blkno,
    const vic_block_t* blocks,
    size_t nblocks)
{
    device_t* device = (device_t*)device_;
    off_t off;
    size_t size;

    if (!_valid_device(device))
        return -1;

    off = blkno * sizeof(vic_block_t);

    if (lseek(device->fd, off, SEEK_SET) != off)
        return -1;

    size = nblocks * sizeof(vic_block_t);

    if (write(device->fd, blocks, size) != (ssize_t)size)
        return -1;

    return 0;
}

size_t _count(vic_device_t* device_)
{
    device_t* device = (device_t*)device_;
    struct stat st;

    if (!_valid_device(device))
        return (size_t)-1;

    if (fstat(device->fd, &st) != 0)
        return (size_t)-1;

    if (S_ISREG(st.st_mode))
    {
        if (st.st_size % sizeof(vic_block_t))
            return (size_t)-1;

        return st.st_size / sizeof(vic_block_t);
    }
    else
    {
        size_t size;

        if (ioctl(device->fd, BLKGETSIZE, &size) != 0)
            return (size_t)-1;

        return size;
    }
}

vic_device_t* vic_open_device(const char* path)
{
    vic_device_t* ret = NULL;
    device_t* device = NULL;

    if (!path)
        return NULL;

    if (!(device = calloc(1, sizeof(device_t))))
        goto done;

    device->magic = MAGIC;

    if (vic_strlcpy(device->path, path, PATH_MAX) >= PATH_MAX)
        goto done;

    if ((device->fd = open(path, O_RDWR)) < 0)
        goto done;

    device->base.get = _get;
    device->base.put = _puts;
    device->base.count = _count;

    ret = &device->base;
    device = NULL;

done:

    if (device)
        free(device);

    return ret;
}

int vic_close_device(vic_device_t* device_)
{
    device_t* device = (device_t*)device_;

    if (!_valid_device(device))
        return -1;

    close(device->fd);
    free(device);

    return 0;
}

const char* vic_get_device_path(vic_device_t* device_)
{
    device_t* device = (device_t*)device_;

    if (!_valid_device(device))
        return NULL;

    return device->path;
}

size_t vic_get_device_size(const char* path)
{
    size_t ret = (size_t)-1;
    int fd = -1;
    size_t size;
    struct stat st;

    if (!path)
        goto done;

    if ((fd = open(path, O_RDONLY)) < 0)
        goto done;

    if (fstat(fd, &st) != 0)
        goto done;

    if (S_ISREG(st.st_mode))
    {
        size = st.st_size;
    }
    else
    {
        if (ioctl(fd, BLKGETSIZE64, &size) != 0)
            goto done;
    }

    ret = size;

done:

    if (fd >= 0)
        close(fd);

    return ret;
}
