#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
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

int main(void) {
    const char *parent = getenv("KERNAL_STEP33_PROBE_PARENT");
    if (parent == NULL || parent[0] == '\0') {
        parent = "/tmp";
    }
    if (parent[0] != '/') {
        errno = EINVAL;
        fail("fs.probe-parent-absolute");
    }

    char dir_template[512];
    int template_len = snprintf(
        dir_template,
        sizeof(dir_template),
        "%s%s%s",
        parent,
        parent[strlen(parent) - 1] == '/' ? "" : "/",
        "kernal-fs-probe-XXXXXX"
    );
    if (template_len < 0 || (size_t)template_len >= sizeof(dir_template)) {
        errno = ENAMETOOLONG;
        fail("fs.probe-parent-length");
    }
    printf("INFO fs.probe-parent=%s\n", parent);

    char *dir = mkdtemp(dir_template);
    if (dir == NULL) {
        fail("fs.mkdtemp");
    }

    char first[512];
    char second[512];
    snprintf(first, sizeof(first), "%s/a", dir);
    snprintf(second, sizeof(second), "%s/b", dir);

    int fd = open(first, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0640);
    if (fd < 0) {
        fail("fs.open-create");
    }
    require_true(write(fd, "abc", 3) == 3, "fs.write");
    require_true(fsync(fd) == 0, "fs.fsync-initial");
    require_true(pwrite(fd, "Z", 1, 1) == 1, "fs.pwrite");

    char small[4] = {0};
    require_true(pread(fd, small, 3, 0) == 3 && memcmp(small, "aZc", 3) == 0, "fs.pread-after-pwrite");
    require_true(ftruncate(fd, 8192) == 0, "fs.ftruncate-grow");

    unsigned char *map = mmap(NULL, 8192, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (map == MAP_FAILED) {
        fail("fs.mmap-shared");
    }
    map[4096] = 0x5a;
    require_true(msync(map, 8192, MS_SYNC) == 0, "fs.msync");
    require_true(munmap(map, 8192) == 0, "fs.munmap");
    require_true(fsync(fd) == 0, "fs.fsync-after-mmap");
    require_true(close(fd) == 0, "fs.close-first");

    require_true(rename(first, second) == 0, "fs.rename");
    int dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        fail("fs.open-directory");
    }
    require_true(fsync(dirfd) == 0, "fs.directory-fsync-after-rename");
    require_true(close(dirfd) == 0, "fs.close-directory");

    fd = open(second, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fail("fs.reopen-renamed");
    }
    unsigned char byte = 0;
    require_true(pread(fd, &byte, 1, 4096) == 1 && byte == 0x5a, "fs.reopen-mmap-byte");
    struct stat st;
    require_true(fstat(fd, &st) == 0 && st.st_size == 8192, "fs.stat-size");
    printf("INFO fs.mode=%o uid=%lu gid=%lu size=%lld\n", (unsigned int)(st.st_mode & 07777), (unsigned long)st.st_uid, (unsigned long)st.st_gid, (long long)st.st_size);
    require_true(close(fd) == 0, "fs.close-renamed");

    require_true(unlink(second) == 0, "fs.unlink");
    dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        fail("fs.open-directory-after-unlink");
    }
    require_true(fsync(dirfd) == 0, "fs.directory-fsync-after-unlink");
    require_true(close(dirfd) == 0, "fs.close-directory-after-unlink");
    require_true(rmdir(dir) == 0, "fs.rmdir");

    puts("PASS step33.filesystem-probe.complete");
    return 0;
}
