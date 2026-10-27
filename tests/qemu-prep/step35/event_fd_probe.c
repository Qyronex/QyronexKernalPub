#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/inotify.h>
#include <sys/mman.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
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

static int make_epoll(void) {
    int fd = epoll_create1(EPOLL_CLOEXEC);
    if (fd < 0) {
        fail("epoll_create1");
    }
    return fd;
}

static void test_epoll_level(void) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) != 0) fail("level.pipe2");
    int ep = make_epoll();
    struct epoll_event add = {.events = EPOLLIN, .data.u64 = 0x11};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, pipefd[0], &add) != 0) fail("level.epoll_ctl_add");
    if (write(pipefd[1], "xy", 2) != 2) fail("level.write");
    struct epoll_event out[2];
    int n = epoll_wait(ep, out, 2, 1000);
    require_true(n == 1 && out[0].data.u64 == 0x11 && (out[0].events & EPOLLIN), "epoll.level.first-ready");
    n = epoll_wait(ep, out, 2, 0);
    require_true(n == 1 && (out[0].events & EPOLLIN), "epoll.level.remains-ready");
    char buffer[2];
    require_true(read(pipefd[0], buffer, sizeof(buffer)) == 2, "epoll.level.drain");
    n = epoll_wait(ep, out, 2, 0);
    require_true(n == 0, "epoll.level.clears-after-drain");
    close(ep); close(pipefd[0]); close(pipefd[1]);
}

static void test_epoll_edge(void) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) != 0) fail("edge.pipe2");
    int ep = make_epoll();
    struct epoll_event add = {.events = EPOLLIN | EPOLLET, .data.u64 = 0x22};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, pipefd[0], &add) != 0) fail("edge.epoll_ctl_add");
    if (write(pipefd[1], "ab", 2) != 2) fail("edge.write.initial");
    struct epoll_event out[2];
    int n = epoll_wait(ep, out, 2, 1000);
    require_true(n == 1 && out[0].data.u64 == 0x22, "epoll.edge.first-transition");
    char one;
    require_true(read(pipefd[0], &one, 1) == 1, "epoll.edge.partial-read");
    n = epoll_wait(ep, out, 2, 50);
    require_true(n == 0, "epoll.edge.no-repeat-without-transition");
    require_true(read(pipefd[0], &one, 1) == 1, "epoll.edge.drain");
    require_true(write(pipefd[1], "c", 1) == 1, "epoll.edge.write-new-transition");
    n = epoll_wait(ep, out, 2, 1000);
    require_true(n == 1 && out[0].data.u64 == 0x22, "epoll.edge.new-transition");
    close(ep); close(pipefd[0]); close(pipefd[1]);
}

static void test_epoll_oneshot(void) {
    int pipefd[2];
    if (pipe2(pipefd, O_CLOEXEC | O_NONBLOCK) != 0) fail("oneshot.pipe2");
    int ep = make_epoll();
    struct epoll_event event = {.events = EPOLLIN | EPOLLONESHOT, .data.u64 = 0x33};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, pipefd[0], &event) != 0) fail("oneshot.epoll_ctl_add");
    require_true(write(pipefd[1], "z", 1) == 1, "epoll.oneshot.write");
    struct epoll_event out[2];
    int n = epoll_wait(ep, out, 2, 1000);
    require_true(n == 1 && out[0].data.u64 == 0x33, "epoll.oneshot.first-ready");
    n = epoll_wait(ep, out, 2, 50);
    require_true(n == 0, "epoll.oneshot.disabled-after-delivery");
    if (epoll_ctl(ep, EPOLL_CTL_MOD, pipefd[0], &event) != 0) fail("oneshot.epoll_ctl_mod");
    n = epoll_wait(ep, out, 2, 1000);
    require_true(n == 1 && out[0].data.u64 == 0x33, "epoll.oneshot.rearm");
    close(ep); close(pipefd[0]); close(pipefd[1]);
}

static void test_epoll_fd_reuse(void) {
    int first[2];
    if (pipe2(first, O_CLOEXEC | O_NONBLOCK) != 0) fail("reuse.first-pipe");
    int watched = first[0];
    int ep = make_epoll();
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x44};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, watched, &event) != 0) fail("reuse.epoll_ctl_add");
    close(first[0]);
    int second[2];
    if (pipe2(second, O_CLOEXEC | O_NONBLOCK) != 0) fail("reuse.second-pipe");
    if (second[0] != watched) {
        if (dup2(second[0], watched) != watched) fail("reuse.dup2");
        close(second[0]); second[0] = watched;
    }
    require_true(write(second[1], "r", 1) == 1, "epoll.reuse.write-replacement");
    struct epoll_event out;
    int n = epoll_wait(ep, &out, 1, 50);
    require_true(n == 0, "epoll.reuse.old-watch-not-redirected");
    close(ep); close(first[1]); close(second[0]); close(second[1]);
}

static void test_eventfd(void) {
    int fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (fd < 0) fail("eventfd.create");
    uint64_t value = 0;
    errno = 0;
    ssize_t got = read(fd, &value, sizeof(value));
    require_true(got == -1 && errno == EAGAIN, "eventfd.empty-nonblock-eagain");
    uint64_t written = 3;
    require_true(write(fd, &written, sizeof(written)) == (ssize_t)sizeof(written), "eventfd.write-counter");
    int ep = make_epoll();
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x55};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) != 0) fail("eventfd.epoll_ctl_add");
    struct epoll_event out;
    int n = epoll_wait(ep, &out, 1, 1000);
    require_true(n == 1 && (out.events & EPOLLIN), "eventfd.epoll-ready");
    require_true(read(fd, &value, sizeof(value)) == (ssize_t)sizeof(value) && value == 3, "eventfd.read-counter");
    n = epoll_wait(ep, &out, 1, 0);
    require_true(n == 0, "eventfd.not-ready-after-read");
    close(ep); close(fd);
}

static void test_timerfd(void) {
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (fd < 0) fail("timerfd.create");
    struct itimerspec spec = {0};
    spec.it_value.tv_nsec = 10 * 1000 * 1000;
    if (timerfd_settime(fd, 0, &spec, NULL) != 0) fail("timerfd.settime");
    int ep = make_epoll();
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x66};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) != 0) fail("timerfd.epoll_ctl_add");
    struct epoll_event out;
    int n = epoll_wait(ep, &out, 1, 1000);
    require_true(n == 1 && (out.events & EPOLLIN), "timerfd.expiration-ready");
    uint64_t expirations = 0;
    require_true(read(fd, &expirations, sizeof(expirations)) == (ssize_t)sizeof(expirations) && expirations >= 1, "timerfd.expiration-count");
    close(ep); close(fd);
}

static void test_signalfd(void) {
    sigset_t set; sigset_t old;
    sigemptyset(&set); sigaddset(&set, SIGUSR1);
    if (sigprocmask(SIG_BLOCK, &set, &old) != 0) fail("signalfd.block");
    int fd = signalfd(-1, &set, SFD_CLOEXEC | SFD_NONBLOCK);
    if (fd < 0) fail("signalfd.create");
    if (kill(getpid(), SIGUSR1) != 0) fail("signalfd.kill");
    struct signalfd_siginfo info;
    ssize_t got = read(fd, &info, sizeof(info));
    require_true(got == (ssize_t)sizeof(info) && info.ssi_signo == SIGUSR1, "signalfd.masked-delivery");
    close(fd);
    if (sigprocmask(SIG_SETMASK, &old, NULL) != 0) fail("signalfd.restore-mask");
}

static void test_inotify(void) {
    char template[] = "/tmp/kernal-inotify-XXXXXX";
    char *dir = mkdtemp(template);
    if (dir == NULL) fail("inotify.mkdtemp");
    int fd = inotify_init1(IN_CLOEXEC);
    if (fd < 0) fail("inotify.init");
    uint32_t wanted = IN_CREATE | IN_MOVED_FROM | IN_MOVED_TO | IN_DELETE;
    int wd = inotify_add_watch(fd, dir, wanted);
    if (wd < 0) fail("inotify.add-watch");
    char a[512]; char b[512];
    snprintf(a, sizeof(a), "%s/a", dir); snprintf(b, sizeof(b), "%s/b", dir);
    int file = open(a, O_CREAT | O_WRONLY | O_CLOEXEC, 0600);
    if (file < 0) fail("inotify.create-file");
    close(file);
    if (rename(a, b) != 0) fail("inotify.rename");
    if (unlink(b) != 0) fail("inotify.unlink");
    char buffer[8192];
    ssize_t size = read(fd, buffer, sizeof(buffer));
    if (size < 0) fail("inotify.read");
    uint32_t seen = 0;
    for (char *cursor = buffer; cursor < buffer + size;) {
        struct inotify_event *event = (struct inotify_event *)cursor;
        seen |= event->mask; cursor += sizeof(*event) + event->len;
    }
    require_true((seen & wanted) == wanted, "inotify.create-move-delete");
    close(fd);
    if (rmdir(dir) != 0) fail("inotify.rmdir");
}

static void test_memfd_seals(void) {
    int fd = memfd_create("kernal-step35", MFD_CLOEXEC | MFD_ALLOW_SEALING);
    if (fd < 0) fail("memfd.create");
    if (ftruncate(fd, 4096) != 0) fail("memfd.initial-size");
    int seals = F_SEAL_GROW | F_SEAL_SHRINK;
    if (fcntl(fd, F_ADD_SEALS, seals) != 0) fail("memfd.add-seals");
    int observed = fcntl(fd, F_GET_SEALS);
    require_true(observed >= 0 && (observed & seals) == seals, "memfd.get-seals");
    errno = 0;
    int rc = ftruncate(fd, 8192);
    require_true(rc == -1 && errno == EPERM, "memfd.grow-sealed-eperm");
    close(fd);
}

static void test_pidfd_lifecycle(void) {
#ifdef SYS_pidfd_open
    int sync_pipe[2];
    if (pipe2(sync_pipe, O_CLOEXEC) != 0) fail("pidfd.pipe2");
    pid_t child = fork();
    if (child < 0) fail("pidfd.fork");
    if (child == 0) {
        close(sync_pipe[1]);
        char release = 0;
        ssize_t got = read(sync_pipe[0], &release, 1);
        close(sync_pipe[0]);
        _exit(got == 1 && release == 'x' ? 0 : 121);
    }
    close(sync_pipe[0]);
    int pidfd = (int)syscall(SYS_pidfd_open, child, 0U);
    if (pidfd < 0) fail("pidfd.open");
    int ep = make_epoll();
    struct epoll_event event = {.events = EPOLLIN, .data.u64 = 0x77};
    if (epoll_ctl(ep, EPOLL_CTL_ADD, pidfd, &event) != 0) fail("pidfd.epoll_ctl_add");
    require_true(write(sync_pipe[1], "x", 1) == 1, "pidfd.release-child");
    close(sync_pipe[1]);
    struct epoll_event out;
    int n = epoll_wait(ep, &out, 1, 1000);
    require_true(n == 1 && out.data.u64 == 0x77 && (out.events & EPOLLIN), "pidfd.exit-readiness");
    int status = 0;
    if (waitpid(child, &status, 0) != child) fail("pidfd.waitpid");
    require_true(WIFEXITED(status) && WEXITSTATUS(status) == 0, "pidfd.child-exit-zero");
    close(ep); close(pidfd);
    puts("INFO pidfd.open supported=1");
#else
    puts("INFO pidfd.open supported=0 reason=SYS_pidfd_open-not-defined");
#endif
}

static void test_close_range(void) {
    int fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail("close-range.open");
    if (close_range((unsigned int)fd, (unsigned int)fd, 0) != 0) fail("close-range.call");
    errno = 0;
    int rc = fcntl(fd, F_GETFD);
    require_true(rc == -1 && errno == EBADF, "close-range.closed-fd");
}

int main(void) {
    test_epoll_level();
    test_epoll_edge();
    test_epoll_oneshot();
    test_epoll_fd_reuse();
    test_eventfd();
    test_timerfd();
    test_signalfd();
    test_inotify();
    test_memfd_seals();
    test_pidfd_lifecycle();
    test_close_range();
    puts("PASS step35.event-fd-probe.complete");
    return 0;
}
