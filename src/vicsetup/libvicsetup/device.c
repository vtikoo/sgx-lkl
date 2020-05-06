#include <sys/stat.h>
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <linux/fs.h>
#include <sys/ioctl.h>

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
