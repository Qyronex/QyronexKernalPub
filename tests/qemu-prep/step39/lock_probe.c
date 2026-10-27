#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void fail(const char *name) {
    fprintf(stderr, "FAIL %s errno=%d (%s)\n", name, errno, strerror(errno));
    exit(1);
}

static void require_true(int condition, const char *name) {
    if (!condition) {
        errno = 0;
        fail(name);
    }
    printf("PASS %s\n", name);
}

static void wait_child(pid_t child, const char *name) {
    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        fail(name);
    }
    require_true(WIFEXITED(status) && WEXITSTATUS(status) == 0, name);
}

static void test_flock(const char *path) {
    int parent = open(path, O_RDWR | O_CLOEXEC);
    if (parent < 0) {
        fail("flock.open-parent");
    }
    if (flock(parent, LOCK_EX | LOCK_NB) != 0) {
        fail("flock.parent-lock");
    }

    pid_t child = fork();
    if (child < 0) {
        fail("flock.fork");
    }
    if (child == 0) {
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            _exit(101);
        }
        errno = 0;
        int rc = flock(fd, LOCK_EX | LOCK_NB);
        int saved = errno;
        close(fd);
        if (rc == -1 && (saved == EWOULDBLOCK || saved == EAGAIN)) {
            _exit(0);
        }
        _exit(102);
    }
    wait_child(child, "flock.contention-eagain");
    require_true(flock(parent, LOCK_UN) == 0, "flock.unlock");
    close(parent);
}

static void test_fcntl_lock(const char *path) {
    int parent = open(path, O_RDWR | O_CLOEXEC);
    if (parent < 0) {
        fail("fcntl.open-parent");
    }
    struct flock lock = {
        .l_type = F_WRLCK,
        .l_whence = SEEK_SET,
        .l_start = 0,
        .l_len = 0,
        .l_pid = 0,
    };
    if (fcntl(parent, F_SETLK, &lock) != 0) {
        fail("fcntl.parent-lock");
    }

    pid_t child = fork();
    if (child < 0) {
        fail("fcntl.fork");
    }
    if (child == 0) {
        int fd = open(path, O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            _exit(111);
        }
        struct flock child_lock = lock;
        errno = 0;
        int rc = fcntl(fd, F_SETLK, &child_lock);
        int saved = errno;
        close(fd);
        if (rc == -1 && (saved == EACCES || saved == EAGAIN)) {
            _exit(0);
        }
        _exit(112);
    }
    wait_child(child, "fcntl.contention-eacces-or-eagain");

    lock.l_type = F_UNLCK;
    require_true(fcntl(parent, F_SETLK, &lock) == 0, "fcntl.unlock");
    close(parent);
}

int main(void) {
    char path[] = "/tmp/kernal-lock-probe-XXXXXX";
    int seed = mkstemp(path);
    if (seed < 0) {
        fail("lock.mkstemp");
    }
    require_true(write(seed, "lock", 4) == 4, "lock.seed-write");
    close(seed);

    test_flock(path);
    test_fcntl_lock(path);

    require_true(unlink(path) == 0, "lock.unlink");
    puts("PASS step39.lock-probe.complete");
    return 0;
}
