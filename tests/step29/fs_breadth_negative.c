// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef SYS_getcwd
#define SYS_getcwd 17
#endif
#ifndef SYS_openat2
#define SYS_openat2 437
#endif
#ifndef SYS_renameat2
#define SYS_renameat2 276
#endif
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE (1U << 0)
#endif
#ifndef RESOLVE_NO_XDEV
#define RESOLVE_NO_XDEV 0x01
#endif
#ifndef RESOLVE_BENEATH
#define RESOLVE_BENEATH 0x08
#endif
#ifndef AT_REMOVEDIR
#define AT_REMOVEDIR 0x200
#endif

struct open_how_v0 {
    uint64_t flags;
    uint64_t mode;
    uint64_t resolve;
};

struct open_how_extended {
    struct open_how_v0 how;
    uint64_t extension;
};

static int failed_with(long result, int expected)
{
    return result == -1 && errno == expected ? 0 : -1;
}

static int failed_write_state_unchanged(int fd, const struct stat *before, char expected_byte)
{
    struct stat after;
    if (fstat(fd, &after) != 0)
        return -1;
    if (after.st_size != before->st_size)
        return -1;
    if (after.st_mtim.tv_sec != before->st_mtim.tv_sec
        || after.st_mtim.tv_nsec != before->st_mtim.tv_nsec)
        return -1;
    if (after.st_ctim.tv_sec != before->st_ctim.tv_sec
        || after.st_ctim.tv_nsec != before->st_ctim.tv_nsec)
        return -1;

    char observed = 0;
    if (pread(fd, &observed, 1, 0) != 1 || observed != expected_byte)
        return -1;
    return 0;
}

static long raw_getcwd(char *buffer, size_t size)
{
    errno = 0;
    return syscall(SYS_getcwd, buffer, size);
}

static long raw_openat2(int dirfd, const char *path, const void *how, size_t size)
{
    errno = 0;
    return syscall(SYS_openat2, dirfd, path, how, size);
}

static long raw_renameat2(
    int olddirfd,
    const char *oldpath,
    int newdirfd,
    const char *newpath,
    unsigned int flags)
{
    errno = 0;
    return syscall(SYS_renameat2, olddirfd, oldpath, newdirfd, newpath, flags);
}

int main(void)
{
    umask(0);
    if (mkdirat(AT_FDCWD, "step29-neg", 0755) != 0)
        return 10;
    if (chdir("step29-neg") != 0)
        return 11;
    if (mkdirat(AT_FDCWD, "dir", 0755) != 0)
        return 12;

    char tiny_cwd[2];
    if (failed_with(raw_getcwd(tiny_cwd, sizeof(tiny_cwd)), ERANGE) != 0)
        return 15;

    int regular = openat(AT_FDCWD, "regular", O_CREAT | O_EXCL | O_RDWR, 0644);
    if (regular < 0)
        return 13;
    int target = openat(AT_FDCWD, "target", O_CREAT | O_EXCL | O_RDWR, 0644);
    if (target < 0)
        return 14;

    char byte = 'x';
    errno = 0;
    if (failed_with(write(-1, &byte, 1), EBADF) != 0)
        return 16;

    const char seed = 's';
    if (write(regular, &seed, 1) != 1)
        return 100;
    if (lseek(regular, 0, SEEK_SET) != 0)
        return 101;
    struct stat before_failed_write;
    if (fstat(regular, &before_failed_write) != 0 || before_failed_write.st_size != 1)
        return 102;

    off_t before_fault = lseek(regular, 0, SEEK_CUR);
    if (before_fault != 0)
        return 17;
    errno = 0;
    if (failed_with(write(regular, (const void *)(uintptr_t)1, 1), EFAULT) != 0)
        return 18;
    if (lseek(regular, 0, SEEK_CUR) != before_fault)
        return 19;
    if (failed_write_state_unchanged(regular, &before_failed_write, seed) != 0)
        return 103;

    errno = 0;
    if (failed_with(pwrite(regular, (const void *)(uintptr_t)1, 1, 0), EFAULT) != 0)
        return 25;
    if (lseek(regular, 0, SEEK_CUR) != before_fault)
        return 26;
    if (failed_write_state_unchanged(regular, &before_failed_write, seed) != 0)
        return 104;

    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
        return 27;
    size_t page = (size_t)page_size;
    void *fault_window = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (fault_window == MAP_FAILED)
        return 28;
    if (munmap((char *)fault_window + page, page) != 0)
        return 29;
    char *partial = (char *)fault_window + page - 4;
    partial[0] = 'a';
    partial[1] = 'b';
    partial[2] = 'c';
    partial[3] = 'd';

    if (lseek(regular, 0, SEEK_SET) != 0)
        return 81;
    ssize_t partial_write = write(regular, partial, 8);
    if (partial_write != 4)
        return 82;
    if (lseek(regular, 0, SEEK_CUR) != 4)
        return 83;
    char verify[4] = {0};
    if (pread(regular, verify, sizeof(verify), 0) != (ssize_t)sizeof(verify))
        return 84;
    if (verify[0] != 'a' || verify[1] != 'b' || verify[2] != 'c' || verify[3] != 'd')
        return 85;
    struct stat after_partial_write;
    if (fstat(regular, &after_partial_write) != 0 || after_partial_write.st_size != 4)
        return 105;

    off_t before_partial_pwrite = lseek(regular, 0, SEEK_CUR);
    if (before_partial_pwrite != 4)
        return 86;
    ssize_t partial_pwrite = pwrite(regular, partial, 8, 16);
    if (partial_pwrite != 4)
        return 87;
    if (lseek(regular, 0, SEEK_CUR) != before_partial_pwrite)
        return 88;
    char positional_verify[4] = {0};
    if (pread(regular, positional_verify, sizeof(positional_verify), 16)
        != (ssize_t)sizeof(positional_verify))
        return 89;
    if (positional_verify[0] != 'a' || positional_verify[1] != 'b'
        || positional_verify[2] != 'c' || positional_verify[3] != 'd')
        return 90;
    struct stat after_partial_pwrite;
    if (fstat(regular, &after_partial_pwrite) != 0 || after_partial_pwrite.st_size != 20)
        return 106;
    char hole[12];
    if (pread(regular, hole, sizeof(hole), 4) != (ssize_t)sizeof(hole))
        return 107;
    for (size_t index = 0; index < sizeof(hole); ++index) {
        if (hole[index] != 0)
            return 108;
    }
    char beyond = 0;
    if (pread(regular, &beyond, 1, 20) != 0)
        return 109;

    errno = 0;
    if (failed_with(unlinkat(AT_FDCWD, "dir", 0), EISDIR) != 0)
        return 20;
    errno = 0;
    if (failed_with(unlinkat(AT_FDCWD, "regular", AT_REMOVEDIR), ENOTDIR) != 0)
        return 21;

    if (failed_with(
            raw_renameat2(AT_FDCWD, "regular", AT_FDCWD, "target", RENAME_NOREPLACE),
            EEXIST) != 0)
        return 22;
    if (failed_with(
            raw_renameat2(AT_FDCWD, "regular", AT_FDCWD, "renamed", 0x80000000U),
            EINVAL) != 0)
        return 23;

    errno = 0;
    if (failed_with(pwrite(regular, &byte, 1, (off_t)-1), EINVAL) != 0)
        return 24;

    struct open_how_v0 how = {
        .flags = O_RDONLY | O_DIRECTORY,
        .mode = 0,
        .resolve = 0,
    };
    if (failed_with(raw_openat2(AT_FDCWD, ".", &how, sizeof(how) - 1), EINVAL) != 0)
        return 30;

    struct open_how_extended extended = {
        .how = how,
        .extension = 1,
    };
    if (failed_with(raw_openat2(AT_FDCWD, ".", &extended, sizeof(extended)), E2BIG) != 0)
        return 31;

    extended.extension = 0;
    long extended_fd = raw_openat2(AT_FDCWD, ".", &extended, sizeof(extended));
    if (extended_fd < 0)
        return 32;
    if (close((int)extended_fd) != 0)
        return 33;

    how.resolve = UINT64_C(1) << 63;
    if (failed_with(raw_openat2(AT_FDCWD, ".", &how, sizeof(how)), EINVAL) != 0)
        return 34;

    how.resolve = 0;
    how.mode = 0600;
    if (failed_with(raw_openat2(AT_FDCWD, ".", &how, sizeof(how)), EINVAL) != 0)
        return 35;

    how.mode = 0;
    if (failed_with(raw_openat2(AT_FDCWD, ".", (const void *)(uintptr_t)1, sizeof(how)), EFAULT) != 0)
        return 36;

    int dirfd = openat(AT_FDCWD, "dir", O_RDONLY | O_DIRECTORY);
    if (dirfd < 0)
        return 40;

    how.resolve = RESOLVE_BENEATH;
    if (failed_with(raw_openat2(dirfd, ".", &how, sizeof(how)), EINVAL) != 0)
        return 41;
    if (failed_with(raw_openat2(dirfd, "../target", &how, sizeof(how)), EINVAL) != 0)
        return 42;

    how.resolve = RESOLVE_NO_XDEV;
    if (failed_with(raw_openat2(dirfd, ".", &how, sizeof(how)), EINVAL) != 0)
        return 43;
    if (close(dirfd) != 0)
        return 44;

    if (munmap(fault_window, page) != 0)
        return 91;
    if (close(target) != 0 || close(regular) != 0)
        return 50;
    if (unlinkat(AT_FDCWD, "target", 0) != 0)
        return 51;
    if (unlinkat(AT_FDCWD, "regular", 0) != 0)
        return 52;
    if (unlinkat(AT_FDCWD, "dir", AT_REMOVEDIR) != 0)
        return 53;
    if (chdir("/") != 0)
        return 54;
    if (unlinkat(AT_FDCWD, "step29-neg", AT_REMOVEDIR) != 0)
        return 55;

    if (mkdirat(AT_FDCWD, "step29-root-clamp", 0755) != 0)
        return 60;
    if (chdir("/step29-root-clamp") != 0)
        return 61;
    if (mkdirat(AT_FDCWD, "deep", 0755) != 0 || chdir("deep") != 0)
        return 62;

    int clamped = openat(AT_FDCWD, "../../../clamped", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (clamped < 0)
        return 63;
    if (close(clamped) != 0)
        return 64;
    if (faccessat(AT_FDCWD, "/clamped", F_OK, 0) != 0)
        return 65;

    int symlink_target = openat(AT_FDCWD, "/symlink-target", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (symlink_target < 0 || close(symlink_target) != 0)
        return 66;
    if (symlinkat("../../../symlink-target", AT_FDCWD, "up") != 0)
        return 67;
    int followed = openat(AT_FDCWD, "up", O_RDONLY);
    if (followed < 0 || close(followed) != 0)
        return 68;

    if (unlinkat(AT_FDCWD, "up", 0) != 0)
        return 69;
    if (chdir("/") != 0)
        return 70;
    if (unlinkat(AT_FDCWD, "clamped", 0) != 0 || unlinkat(AT_FDCWD, "symlink-target", 0) != 0)
        return 71;
    if (unlinkat(AT_FDCWD, "step29-root-clamp/deep", AT_REMOVEDIR) != 0)
        return 72;
    if (unlinkat(AT_FDCWD, "step29-root-clamp", AT_REMOVEDIR) != 0)
        return 73;

    static const char success[] = "KERNAL/S29FSN: negative filesystem contract passed\n";
    if (write(STDERR_FILENO, success, sizeof(success) - 1) != (ssize_t)(sizeof(success) - 1))
        return 80;

    return 0;
}
