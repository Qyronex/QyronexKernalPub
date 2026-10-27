#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/random.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
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

static void print_termios_reference(const struct termios *state) {
    printf(
        "INFO tty.flags iflag=%lu oflag=%lu cflag=%lu lflag=%lu\n",
        (unsigned long)state->c_iflag,
        (unsigned long)state->c_oflag,
        (unsigned long)state->c_cflag,
        (unsigned long)state->c_lflag
    );
    printf(
        "INFO tty.termios-size bytes=%zu nccs=%u\n",
        sizeof(*state),
        (unsigned int)NCCS
    );
    printf(
        "INFO tty.speeds ispeed=%lu ospeed=%lu\n",
        (unsigned long)cfgetispeed(state),
        (unsigned long)cfgetospeed(state)
    );
    printf("INFO tty.cc hex=");
    for (size_t i = 0; i < NCCS; i++) {
        printf("%02x", (unsigned int)(unsigned char)state->c_cc[i]);
    }
    putchar('\n');
}

static void probe_device_baseline(void) {
    unsigned char buffer[32];
    unsigned char byte = 0x5a;

    int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
    if (fd < 0) fail("dev.open-null");
    if (write(fd, &byte, 1) != 1) fail("dev.write-null");
    ssize_t got = read(fd, &byte, 1);
    if (got != 0) fail("dev.read-null");
    close(fd);
    puts("PASS dev.null-semantics");

    memset(buffer, 0xa5, sizeof(buffer));
    fd = open("/dev/zero", O_RDONLY | O_CLOEXEC);
    if (fd < 0) fail("dev.open-zero");
    got = read(fd, buffer, sizeof(buffer));
    if (got != (ssize_t)sizeof(buffer)) fail("dev.read-zero");
    close(fd);
    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (buffer[i] != 0) {
            errno = 0;
            fail("dev.zero-content");
        }
    }
    puts("PASS dev.zero-semantics");

    fd = open("/dev/full", O_WRONLY | O_CLOEXEC);
    if (fd < 0) fail("dev.open-full");
    errno = 0;
    ssize_t wrote = write(fd, &byte, 1);
    int saved_errno = errno;
    close(fd);
    if (wrote != -1 || saved_errno != ENOSPC) {
        errno = saved_errno;
        fail("dev.full-enospc");
    }
    puts("PASS dev.full-enospc");

    fd = open("/dev/console", O_WRONLY | O_NOCTTY | O_CLOEXEC);
    if (fd < 0) fail("dev.open-console");
    close(fd);
    puts("PASS dev.console-open");
}

static void probe_entropy_devices(void) {
    unsigned char buffer[32];
    ssize_t got = getrandom(buffer, sizeof(buffer), 0);
    if (got != (ssize_t)sizeof(buffer)) {
        fail("entropy.getrandom");
    }
    printf("INFO entropy.getrandom bytes=%zu\n", sizeof(buffer));

    int urandom = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (urandom < 0) {
        fail("entropy.open-urandom");
    }
    got = read(urandom, buffer, sizeof(buffer));
    if (got != (ssize_t)sizeof(buffer)) {
        close(urandom);
        fail("entropy.read-urandom");
    }
    close(urandom);
    printf("INFO entropy.urandom bytes=%zu\n", sizeof(buffer));

    int random_fd = open("/dev/random", O_RDONLY | O_CLOEXEC | O_NONBLOCK);
    if (random_fd < 0) {
        fail("entropy.open-random");
    }
    errno = 0;
    got = read(random_fd, buffer, 1);
    int saved_errno = errno;
    close(random_fd);
    if (got == 1) {
        puts("INFO entropy.random_nonblock state=ready");
    } else if (got < 0 && saved_errno == EAGAIN) {
        puts("INFO entropy.random_nonblock state=eagain");
    } else {
        errno = saved_errno;
        fail("entropy.read-random-nonblock");
    }
}

static void read_until(int fd, const char *needle, char *transcript, size_t capacity) {
    size_t used = strlen(transcript);
    for (int attempt = 0; attempt < 100; attempt++) {
        if (strstr(transcript, needle) != NULL) {
            return;
        }
        struct pollfd pfd = {.fd = fd, .events = POLLIN | POLLHUP};
        int ready = poll(&pfd, 1, 50);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            fail("pty.poll");
        }
        if (ready == 0) {
            continue;
        }
        if (used + 1 >= capacity) {
            errno = 0;
            fail("pty.transcript-overflow");
        }
        ssize_t got = read(fd, transcript + used, capacity - used - 1);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (errno == EIO && (pfd.revents & POLLHUP)) {
                break;
            }
            fail("pty.read");
        }
        if (got == 0) {
            break;
        }
        used += (size_t)got;
        transcript[used] = '\0';
    }
    fprintf(stderr, "FAIL pty.read-until needle=%s transcript=%s\n", needle, transcript);
    exit(1);
}

int main(void) {
    int master = open("/dev/ptmx", O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (master < 0) {
        fail("pty.open-ptmx");
    }
    if (grantpt(master) != 0) {
        fail("pty.grantpt");
    }
    if (unlockpt(master) != 0) {
        fail("pty.unlockpt");
    }

    char slave_name[256];
    if (ptsname_r(master, slave_name, sizeof(slave_name)) != 0) {
        fail("pty.ptsname_r");
    }
    printf("INFO pty.slave=%s\n", slave_name);

    int slave = open(slave_name, O_RDWR | O_NOCTTY | O_CLOEXEC);
    if (slave < 0) {
        fail("pty.open-slave");
    }

    struct termios termios_state;
    if (tcgetattr(slave, &termios_state) != 0) {
        fail("tty.tcgetattr");
    }
    print_termios_reference(&termios_state);

    struct winsize winsize;
    if (ioctl(slave, TIOCGWINSZ, &winsize) != 0) {
        fail("tty.tiocgwinsz");
    }
    printf("INFO tty.winsize rows=%u cols=%u xpixel=%u ypixel=%u\n", winsize.ws_row, winsize.ws_col, winsize.ws_xpixel, winsize.ws_ypixel);

    errno = 0;
    int rc = ioctl(slave, TIOCGWINSZ, (void *)1);
    require_true(rc == -1 && errno == EFAULT, "tty.bad-pointer-efault");

    errno = 0;
    rc = ioctl(slave, 0xdeadbeefUL, 0);
    require_true(rc == -1 && errno == ENOTTY, "tty.unknown-ioctl-enotty");

    probe_device_baseline();
    probe_entropy_devices();

    pid_t child = fork();
    if (child < 0) {
        fail("pty.fork");
    }
    if (child == 0) {
        close(master);
        if (setsid() < 0) {
            _exit(101);
        }
        if (ioctl(slave, TIOCSCTTY, 0) != 0) {
            _exit(102);
        }
        if (tcsetpgrp(slave, getpgrp()) != 0) {
            _exit(103);
        }
        if (tcgetpgrp(slave) != getpgrp()) {
            _exit(104);
        }
        dprintf(slave, "PTY_PGRP_OK\n");
        if (dup2(slave, STDIN_FILENO) < 0 || dup2(slave, STDOUT_FILENO) < 0 || dup2(slave, STDERR_FILENO) < 0) {
            _exit(105);
        }
        if (slave > STDERR_FILENO) {
            close(slave);
        }
        execl(
            "/bin/sh",
            "sh",
            "-c",
            "printf 'PTY_CHILD_OK\\n'; IFS= read -r line; printf 'PTY_ECHO:%s\\n' \"$line\"",
            (char *)NULL
        );
        _exit(106);
    }

    close(slave);
    char transcript[16384] = {0};
    read_until(master, "PTY_PGRP_OK", transcript, sizeof(transcript));
    read_until(master, "PTY_CHILD_OK", transcript, sizeof(transcript));
    require_true(write(master, "hello\n", 6) == 6, "pty.parent-write");
    read_until(master, "PTY_ECHO:hello", transcript, sizeof(transcript));

    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        fail("pty.waitpid");
    }
    require_true(WIFEXITED(status) && WEXITSTATUS(status) == 0, "pty.child-exit-zero");
    close(master);

    printf("INFO pty.transcript-begin\n%sINFO pty.transcript-end\n", transcript);
    puts("PASS step32.pty-probe.complete");
    return 0;
}
