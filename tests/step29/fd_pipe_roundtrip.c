// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int write_exact(int fd, const char *bytes, size_t len)
{
    return write(fd, bytes, len) == (ssize_t)len ? 0 : -1;
}

int main(void)
{
    /* Canonical inherited 0/1/2 must already exist. dup() proves object-bound stderr aliasing and
     * Linux lowest-free allocation before the pipe pair is created. */
    int stderr_alias = dup(STDERR_FILENO);
    if (stderr_alias != 3)
        return 10;
    static const char alias_marker[] = "KERNAL/S29IO: external stderr alias write passed\n";
    if (write_exact(stderr_alias, alias_marker, sizeof(alias_marker) - 1) != 0)
        return 11;
    if (close(stderr_alias) != 0)
        return 12;

    int pipefd[2] = {-1, -1};
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) != 0)
        return 20;
    if (pipefd[0] != 3 || pipefd[1] != 4)
        return 21;

    int read_fd_flags = fcntl(pipefd[0], F_GETFD);
    int write_fd_flags = fcntl(pipefd[1], F_GETFD);
    if (read_fd_flags < 0 || write_fd_flags < 0 ||
        (read_fd_flags & FD_CLOEXEC) == 0 || (write_fd_flags & FD_CLOEXEC) == 0)
        return 22;

    int read_status = fcntl(pipefd[0], F_GETFL);
    int write_status = fcntl(pipefd[1], F_GETFL);
    if (read_status < 0 || write_status < 0)
        return 23;
    if ((read_status & O_ACCMODE) != O_RDONLY || (read_status & O_NONBLOCK) == 0)
        return 24;
    if ((write_status & O_ACCMODE) != O_WRONLY || (write_status & O_NONBLOCK) == 0)
        return 25;

    struct stat read_stat;
    struct stat write_stat;
    if (fstat(pipefd[0], &read_stat) != 0 || fstat(pipefd[1], &write_stat) != 0)
        return 26;
    if (!S_ISFIFO(read_stat.st_mode) || !S_ISFIFO(write_stat.st_mode))
        return 27;
    if (read_stat.st_dev != write_stat.st_dev || read_stat.st_ino != write_stat.st_ino)
        return 28;

    errno = 0;
    if (lseek(pipefd[0], 0, SEEK_SET) != (off_t)-1 || errno != ESPIPE)
        return 29;

    unsigned char positional = 0;
    errno = 0;
    if (pread(pipefd[0], &positional, 1, 0) != (ssize_t)-1 || errno != ESPIPE)
        return 30;

    /* Replace inherited stdout with an alias of the pipe writer. The next write(1) must therefore
     * enter the pipe by canonical object identity rather than resurrecting the historical numeric
     * stdout path. */
    if (dup3(pipefd[1], STDOUT_FILENO, O_CLOEXEC) != STDOUT_FILENO)
        return 31;
    int redirected_fd_flags = fcntl(STDOUT_FILENO, F_GETFD);
    int redirected_status = fcntl(STDOUT_FILENO, F_GETFL);
    if (redirected_fd_flags < 0 || (redirected_fd_flags & FD_CLOEXEC) == 0)
        return 32;
    if (redirected_status < 0 || (redirected_status & O_ACCMODE) != O_WRONLY ||
        (redirected_status & O_NONBLOCK) == 0)
        return 33;

    struct stat redirected_stat;
    if (fstat(STDOUT_FILENO, &redirected_stat) != 0)
        return 34;
    if (!S_ISFIFO(redirected_stat.st_mode) || redirected_stat.st_dev != read_stat.st_dev ||
        redirected_stat.st_ino != read_stat.st_ino)
        return 35;

    static const char payload[] = "step29-pipe-roundtrip";
    if (write_exact(STDOUT_FILENO, payload, sizeof(payload) - 1) != 0)
        return 36;
    char received[sizeof(payload) - 1];
    ssize_t copied = read(pipefd[0], received, sizeof(received));
    if (copied != (ssize_t)sizeof(received) || memcmp(received, payload, sizeof(received)) != 0)
        return 37;

    /* pipefd[1] and stdout share one writer OFD. Closing the original writer must keep the endpoint
     * live; closing stdout must release the final writer alias, after which the drained reader sees
     * EOF even though it is O_NONBLOCK. */
    if (close(pipefd[1]) != 0)
        return 38;
    if (close(STDOUT_FILENO) != 0)
        return 39;
    char eof_probe = 0;
    if (read(pipefd[0], &eof_probe, 1) != 0)
        return 40;
    if (close(pipefd[0]) != 0)
        return 41;

    static const char success[] = "KERNAL/S29IO: fd-pipe roundtrip passed\n";
    if (write_exact(STDERR_FILENO, success, sizeof(success) - 1) != 0)
        return 42;

    return 0;
}
