// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef SYS_getcwd
#define SYS_getcwd 17
#endif

static int exact_bytes(const char *left, const char *right, size_t len)
{
    return memcmp(left, right, len) == 0 ? 0 : -1;
}

static long raw_getcwd(char *buffer, size_t size)
{
    errno = 0;
    return syscall(SYS_getcwd, buffer, size);
}

int main(void)
{
    char cwd[128];
    if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/") != 0)
        return 10;

    char raw_cwd[128];
    long raw_cwd_len = raw_getcwd(raw_cwd, sizeof(raw_cwd));
    if (raw_cwd_len != 2 || raw_cwd[0] != '/' || raw_cwd[1] != '\0')
        return 61;

    mode_t previous = umask(0027);
    if (previous != 0022)
        return 62;

    if (mkdirat(AT_FDCWD, "step29-work", 0777) != 0)
        return 11;
    if (chdir("step29-work") != 0)
        return 12;
    if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/step29-work") != 0)
        return 13;
    raw_cwd_len = raw_getcwd(raw_cwd, sizeof(raw_cwd));
    if (raw_cwd_len != (long)(sizeof("/step29-work")) || strcmp(raw_cwd, "/step29-work") != 0)
        return 63;

    int dirfd = openat(AT_FDCWD, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return 14;

    int fd = openat(AT_FDCWD, "alpha", O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0666);
    if (fd < 0)
        return 20;

    static const char initial[] = "abcdef";
    if (write(fd, initial, sizeof(initial) - 1) != (ssize_t)(sizeof(initial) - 1))
        return 21;
    off_t shared_before = lseek(fd, 0, SEEK_CUR);
    if (shared_before != (off_t)(sizeof(initial) - 1))
        return 22;

    static const char patch[] = "XY";
    if (pwrite(fd, patch, sizeof(patch) - 1, 2) != (ssize_t)(sizeof(patch) - 1))
        return 23;
    if (lseek(fd, 0, SEEK_CUR) != shared_before)
        return 24;

    char readback[sizeof(initial) - 1];
    if (pread(fd, readback, sizeof(readback), 0) != (ssize_t)sizeof(readback))
        return 25;
    static const char expected[] = "abXYef";
    if (exact_bytes(readback, expected, sizeof(readback)) != 0)
        return 26;

    int dupfd = dup(fd);
    if (dupfd < 0)
        return 64;
    static const char suffix[] = "!";
    if (write(dupfd, suffix, sizeof(suffix) - 1) != (ssize_t)(sizeof(suffix) - 1))
        return 65;
    if (lseek(fd, 0, SEEK_CUR) != shared_before + (off_t)(sizeof(suffix) - 1))
        return 66;
    char suffix_readback = 0;
    if (pread(fd, &suffix_readback, 1, shared_before) != 1 || suffix_readback != '!')
        return 67;
    if (close(dupfd) != 0)
        return 68;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode))
        return 27;
    if ((st.st_mode & 0777) != 0640)
        return 28;

    if (fchmod(fd, 0604) != 0)
        return 29;
    if (fstat(fd, &st) != 0 || (st.st_mode & 0777) != 0604)
        return 30;

    struct timespec times[2] = {
        { .tv_sec = 123, .tv_nsec = 456000000 },
        { .tv_sec = 789, .tv_nsec = 123000000 },
    };
    if (utimensat(AT_FDCWD, "alpha", times, 0) != 0)
        return 31;
    if (fstat(fd, &st) != 0)
        return 32;
    if (st.st_mtim.tv_sec != times[1].tv_sec || st.st_mtim.tv_nsec != times[1].tv_nsec)
        return 33;

    if (linkat(AT_FDCWD, "alpha", AT_FDCWD, "hard", 0) != 0)
        return 40;
    if (symlinkat("alpha", AT_FDCWD, "sym") != 0)
        return 41;
    char link_target[32];
    ssize_t target_len = readlinkat(AT_FDCWD, "sym", link_target, sizeof(link_target));
    if (target_len != 5 || exact_bytes(link_target, "alpha", 5) != 0)
        return 42;

    struct stat hard_st;
    if (fstatat(AT_FDCWD, "hard", &hard_st, 0) != 0)
        return 43;
    if (hard_st.st_ino != st.st_ino || hard_st.st_dev != st.st_dev)
        return 44;

    if (renameat(AT_FDCWD, "hard", AT_FDCWD, "renamed") != 0)
        return 45;
    if (faccessat(AT_FDCWD, "hard", F_OK, 0) == 0 || errno != ENOENT)
        return 46;
    if (faccessat(AT_FDCWD, "renamed", F_OK, 0) != 0)
        return 47;

    if (close(fd) != 0)
        return 50;
    if (unlinkat(AT_FDCWD, "sym", 0) != 0)
        return 51;
    if (unlinkat(AT_FDCWD, "renamed", 0) != 0)
        return 52;
    if (unlinkat(AT_FDCWD, "alpha", 0) != 0)
        return 53;

    if (fchdir(dirfd) != 0)
        return 54;
    if (close(dirfd) != 0)
        return 55;
    if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/step29-work") != 0)
        return 56;

    if (chdir("/") != 0)
        return 57;
    if (unlinkat(AT_FDCWD, "step29-work", AT_REMOVEDIR) != 0)
        return 58;
    if (getcwd(cwd, sizeof(cwd)) == NULL || strcmp(cwd, "/") != 0)
        return 59;

    static const char success[] = "KERNAL/S29FS: mutable filesystem roundtrip passed\n";
    if (write(STDERR_FILENO, success, sizeof(success) - 1) != (ssize_t)(sizeof(success) - 1))
        return 60;

    return 0;
}
