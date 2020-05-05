#include "verity.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <unistd.h>
#include <linux/fs.h>

#include "vic.h"
#include "uuid.h"
#include "hexdump.h"
#include "hash.h"
#include "raise.h"
#include "crypto.h"
#include "round.h"
#include "dm.h"

static vic_result_t _get_file_size(const char* path, size_t* size_out)
{
    vic_result_t result = VIC_UNEXPECTED;
    struct stat st;
    size_t size;
    int fd = -1;

    if (size_out)
        *size_out = 0;

    if (!path || !size_out)
        RAISE(VIC_BAD_PARAMETER);

    if ((fd = open(path, O_RDONLY)) < 0)
        RAISE(VIC_OPEN_FAILED);

    if (fstat(fd, &st) != 0)
        RAISE(VIC_STAT_FAILED);

    if (S_ISREG(st.st_mode))
    {
        size = st.st_size;
    }
    else if (ioctl(fd, BLKGETSIZE64, &size) != 0)
    {
        RAISE(VIC_IOCTL_FAILED);
    }

    *size_out = size;
    result = VIC_OK;

done:

    if (fd >= 0)
        close(fd);

    return result;
}

void vic_verity_dump_sb(vic_verity_sb_t* sb)
{
    if (sb)
    {
        char uuid[VIC_UUID_STRING_SIZE];

        vic_uuid_bin2str(sb->uuid, uuid);

        printf("UUID:\t\t\t%s\n", uuid);
        printf("Hash type:\t\t%u\n", sb->hash_type);
        printf("Data blocks:\t\t%lu\n", sb->data_blocks);
        printf("Data block size:\t%u\n", sb->data_block_size);
        printf("Hash block size:\t%u\n", sb->hash_block_size);
        printf("Hash algorithm:\t\t%s\n", sb->algorithm);
        printf("Salt:\t\t\t");
        vic_hexdump_flat(sb->salt, sb->salt_size);
        printf("\n");
    }
}

vic_result_t vic_verity_format(
    const char* datafile,
    const char* hashfile,
    const char* hash_algorithm,
    const char* uuid,
    const uint8_t* salt,
    size_t salt_size,
    bool need_superblock,
    uint8_t* root_hash,
    size_t* root_hash_size)
{
    vic_result_t result = VIC_UNEXPECTED;
    FILE* is = NULL;
    FILE* os = NULL;
    const size_t blk_sz = 4096;
    size_t nblks;
    size_t digests_per_blk;
    size_t hsize;
    uint8_t salt_buf[VIC_VERITY_MAX_SALT_SIZE];
    char uuid_buf[VIC_UUID_STRING_SIZE];
    size_t nleaves;
    size_t nnodes[32];
    size_t levels = 0;
    size_t total_nodes = 0;
    vic_hash_type_t htype;
    const size_t MIN_DATA_FILE_SIZE = blk_sz * 2;
    uint8_t last_node[blk_sz];

    if (!datafile || !hashfile || !root_hash || !root_hash_size)
        RAISE(VIC_BAD_PARAMETER);

    if (salt)
    {
        if (salt_size <= 0 || salt_size > VIC_VERITY_MAX_SALT_SIZE)
            RAISE(VIC_BAD_PARAMETER);
    }
    else if (salt_size != 0)
    {
        RAISE(VIC_BAD_PARAMETER);
    }

    if (hash_algorithm)
    {
        if ((htype = vic_hash_type(hash_algorithm)) == VIC_HASH_NONE)
            RAISE(VIC_BAD_PARAMETER);

        if ((hsize = vic_hash_size(hash_algorithm)) == (size_t)-1)
            RAISE(VIC_BAD_PARAMETER);
    }
    else
    {
        htype = VIC_HASH_SHA256;
        hsize = VIC_SHA256_SIZE;
    }

    /* Handle the salt parameter or generate a salt if none */
    if (!salt)
    {
        salt_size = hsize;
        vic_luks_random(salt_buf, salt_size);
        salt = salt_buf;
    }

#if 0
    if (hsize != salt_size)
        RAISE(VIC_BAD_PARAMETER);
#endif

    /* Handle the uuid_buf parameter or generate a new UUID */
    if (uuid)
    {
        if (!vic_uuid_valid(uuid))
            RAISE(VIC_BAD_UUID);

        strcpy(uuid_buf, uuid);
    }
    else
    {
        vic_uuid_generate(uuid_buf);
    }

    /* Calculate the number of data blocks */
    {
        size_t size;

        CHECK(_get_file_size(datafile, &size));

        /* File must be a multiple of the block size */
        if (size % blk_sz)
            RAISE(VIC_NOT_BLOCK_MULTIPLE);

        if (size < (ssize_t)MIN_DATA_FILE_SIZE)
            RAISE(VIC_FILE_TOO_SMALL);

        nblks = size / blk_sz;
    }

    /* Calculate the number of digests per blocks */
    digests_per_blk = blk_sz / hsize;

    /* Calculate the number of leaf nodes */
    nleaves = vic_round_up(nblks, digests_per_blk) / digests_per_blk;
    nnodes[levels++] = nleaves;

    /* Save the nodes at the leaf levels */
    size_t n = nleaves;

    /* Calculate the number of interior nodes at each levels */
    while (n > 1)
    {
        n = vic_round_up(n, digests_per_blk) / digests_per_blk;
        nnodes[levels++] = n;
    }

    /* Calculate the total number of nodes at all levels */
    for (size_t i = 0; i < levels; i++)
        total_nodes += nnodes[i];

    /* Open the data file for read */
    if (!(is = fopen(datafile, "rb")))
        RAISE(VIC_OPEN_FAILED);

    /* Open the hash file for read and write */
    if (!(os = fopen(hashfile, "w+")))
        RAISE(VIC_OPEN_FAILED);

    /* Fill the hash file with zero blocks */
    {
        uint8_t zeros[blk_sz];
        size_t nblks = total_nodes;

        if (need_superblock)
            nblks++;

        memset(zeros, 0, sizeof(zeros));

        for (size_t i = 0; i < nblks; i++)
        {
            if (fwrite(zeros, 1, sizeof(zeros), os) != sizeof(zeros))
                RAISE(VIC_WRITE_FAILED);
        }
    }

    /* Write the leaf nodes */
    {
        uint8_t blk[blk_sz];
        uint8_t node[blk_sz];
        size_t node_offset = 0;
        size_t offset;

        /* Calculate the hash file offset to the first leaf node block */
        offset = (total_nodes - nleaves) * blk_sz;

        if (need_superblock)
            offset += blk_sz;

        /* Zero out the node */
        memset(node, 0, sizeof(node));

        while (fread(blk, 1, sizeof(blk), is) == blk_sz)
        {
            vic_hash_t h;

            /* Compute the hash of the current block */
            if (vic_hash2(htype, salt, salt_size, &blk, blk_sz, &h) != 0)
                RAISE(VIC_UNEXPECTED);

            /* Write out the node if full */
            if (node_offset + hsize > blk_sz)
            {
                if (fseek(os, offset, SEEK_SET) != 0)
                    RAISE(VIC_SEEK_FAILED);

                if (fwrite(node, 1, sizeof(node), os) != sizeof(node))
                    RAISE(VIC_WRITE_FAILED);

                memcpy(last_node, node, sizeof(last_node));

                offset += sizeof(node);
                memset(node, 0, sizeof(node));
                node_offset = 0;
            }

            memcpy(node + node_offset, h.u.buf, hsize);
            node_offset += hsize;
        }

        /* Write the final hash file block if any */
        if (node_offset > 0)
        {
            if (fseek(os, offset, SEEK_SET) != 0)
                RAISE(VIC_SEEK_FAILED);

            if (fwrite(node, 1, sizeof(node), os) != sizeof(node))
                RAISE(VIC_WRITE_FAILED);

            memcpy(last_node, node, sizeof(last_node));
        }
    }

    /* Write the interior nodes */
    for (size_t i = 1; i < levels; i++)
    {
        size_t write_offset = 0;
        size_t read_offset = 0;
        size_t num_to_read;
        size_t num_to_write;

        /* Compute the hash file read offset */
        for (size_t j = i; j < levels; j++)
            read_offset += nnodes[j] * blk_sz;

        if (need_superblock)
            read_offset += blk_sz;

        /* Compute the hash file write offset */
        for (size_t j = i + 1; j < levels; j++)
            write_offset += nnodes[j] * blk_sz;

        if (need_superblock)
            write_offset += blk_sz;

        num_to_read = nnodes[i-1];
        num_to_write = nnodes[i];

        /* For each interior node at this level */
        for (size_t j = 0; j < num_to_write; j++)
        {
            uint8_t node[blk_sz];
            size_t node_offset = 0;

            /* Zero out the next interior node */
            memset(node, 0, sizeof(node));

            /* Fill the interior node with hashes */
            while (num_to_read && (node_offset + hsize) <= blk_sz)
            {
                char blk[blk_sz];
                vic_hash_t h;

                /* Read the next block */
                {
                    if (fseek(os, read_offset, SEEK_SET) != 0)
                        RAISE(VIC_SEEK_FAILED);

                    if (fread(blk, 1, blk_sz, os) != blk_sz)
                        RAISE(VIC_READ_FAILED);

                    read_offset += blk_sz;
                }

                /* Compute the hash of this block */
                if (vic_hash2(htype, salt, salt_size, &blk, blk_sz, &h) != 0)
                    RAISE(VIC_UNEXPECTED);

                /* Copy this hash to the new node */
                memcpy(node + node_offset, h.u.buf, hsize);
                node_offset += hsize;

                num_to_read--;
            }

            /* Write out this interior node */
            {
                if (fseek(os, write_offset, SEEK_SET) != 0)
                    RAISE(VIC_SEEK_FAILED);

                if (fwrite(node, 1, blk_sz, os) != blk_sz)
                    RAISE(VIC_WRITE_FAILED);

                memcpy(last_node, node, sizeof(last_node));

                write_offset += blk_sz;
            }
        }
    }

    /* Compute the root hash (from the last block written) */
    {
        vic_hash_t h;

        if (vic_hash2(htype, salt, salt_size, &last_node, blk_sz, &h) != 0)
            RAISE(VIC_UNEXPECTED);

        if (*root_hash_size < hsize)
            RAISE(VIC_BUFFER_TOO_SMALL);

        memcpy(root_hash, &h, hsize);
        *root_hash_size = hsize;
    }

    /* Write the superblock */
    {
        vic_verity_sb_t sb;

        memset(&sb, 0, sizeof(sb));

        memcpy(sb.signature, "verity\0\0", 8);
        sb.version = 1;
        sb.hash_type = 1;

        if (vic_uuid_str2bin(uuid_buf, sb.uuid) != 0)
            RAISE(VIC_UNEXPECTED);

        strcpy(sb.algorithm, vic_hash_name(htype));
        sb.data_block_size = blk_sz;
        sb.hash_block_size = blk_sz;
        sb.data_blocks = nblks;
        memcpy(sb.salt, salt, salt_size);
        sb.salt_size = salt_size;

        if (need_superblock)
        {
            if (fseek(os, 0, SEEK_SET) != 0)
                RAISE(VIC_SEEK_FAILED);

            if (fwrite(&sb, 1, sizeof(sb), os) != sizeof(sb))
                RAISE(VIC_WRITE_FAILED);
        }

#if 0
        vic_verity_dump_sb(&sb);
        printf("Root hash:\t\t");
        vic_hexdump_flat(&root_hash, hsize);
        printf("\n");
#endif
    }

    if (is)
        fclose(is);

    if (os)
        fclose(os);

    result = VIC_OK;

done:
    return result;
}

static vic_result_t _load_super_block(const char* path, vic_verity_sb_t* sb)
{
    vic_result_t result = VIC_UNEXPECTED;
    FILE* is = NULL;

    if (!path || !sb)
        RAISE(VIC_BAD_PARAMETER);

    if (!(is = fopen(path, "rb")))
        RAISE(VIC_OPEN_FAILED);

    if (fread(sb, 1, sizeof(vic_verity_sb_t), is) != sizeof(vic_verity_sb_t))
        RAISE(VIC_READ_FAILED);

    if (memcmp(sb->signature, "verity\0\0", 8) != 0)
        RAISE(VIC_BAD_SIGNATURE);

    result = VIC_OK;

done:

    if (!is)
        fclose(is);

    return result;
}

vic_result_t vic_verity_open(
    const char* dm_name,
    const char* data_dev,
    const char* hash_dev,
    const void* root_hash,
    size_t root_hash_size)
{
    vic_result_t result = VIC_UNEXPECTED;
    size_t data_dev_size;
    vic_verity_sb_t sb;
    size_t num_blocks;

    if (!dm_name || !data_dev || !hash_dev || !root_hash || !root_hash_size)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(_get_file_size(data_dev, &data_dev_size));

    CHECK(_load_super_block(hash_dev, &sb));

    num_blocks = data_dev_size / sb.data_block_size;

    CHECK(vic_dm_create_verity(
        dm_name,
        data_dev,
        hash_dev,
        sb.data_block_size,
        sb.hash_block_size,
        num_blocks,
        sb.version,
        sb.hash_type,
        sb.algorithm,
        root_hash,
        root_hash_size,
        sb.salt,
        sb.salt_size));

    result = VIC_OK;

done:

    return result;
}

static vic_result_t _load_root_hash_block(
    const char* path,
    uint8_t* hash_block,
    size_t hash_block_size)
{
    vic_result_t result = VIC_UNEXPECTED;
    FILE* is = NULL;

    if (!path)
        RAISE(VIC_BAD_PARAMETER);

    if (!(is = fopen(path, "rb")))
        RAISE(VIC_OPEN_FAILED);

    if (fseek(is, hash_block_size, SEEK_SET) != 0)
        RAISE(VIC_SEEK_FAILED);

    if (fread(hash_block, 1, hash_block_size, is) != hash_block_size)
        RAISE(VIC_READ_FAILED);

    result = VIC_OK;

done:

    if (!is)
        fclose(is);

    return result;
}

vic_result_t vic_verity_dump(const char* hash_dev)
{
    vic_result_t result = VIC_UNEXPECTED;
    vic_verity_sb_t sb;
    uint8_t hash_block[4096];

    if (!hash_dev)
        RAISE(VIC_BAD_PARAMETER);

    CHECK(_load_super_block(hash_dev, &sb));

    vic_verity_dump_sb(&sb);

    if (sb.hash_block_size > sizeof(hash_block))
        RAISE(VIC_UNEXPECTED);

    CHECK(_load_root_hash_block(hash_dev, hash_block, sb.hash_block_size));

    /* Print the root hash */
    {
        vic_hash_type_t htype;
        size_t hsize;
        vic_hash_t h;

        if ((htype = vic_hash_type(sb.algorithm)) == VIC_HASH_NONE)
            RAISE(VIC_UNEXPECTED);

        if ((hsize = vic_hash_size(sb.algorithm)) == VIC_HASH_NONE)
            RAISE(VIC_UNEXPECTED);

        if (vic_hash2(
            htype,
            sb.salt,
            sb.salt_size,
            hash_block,
            sb.hash_block_size,
            &h) != 0)
        {
            RAISE(VIC_UNEXPECTED);
        }

        printf("Root hash:\t\t");
        vic_hexdump_flat(h.u.buf, hsize);
        printf("\n");
    }

    result = VIC_OK;

done:

    return result;
}
