#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/bpf.h>
#include <linux/capability.h>
#include <linux/keyctl.h>
#include <linux/netlink.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

static void print_syscall_result(const char *name, long rc, int saved_errno) {
    if (rc >= 0) {
        printf("INFO security.%s state=success value=%ld\n", name, rc);
    } else {
        printf("INFO security.%s state=error errno=%d name=%s\n", name, saved_errno, strerror(saved_errno));
    }
}

static void probe_seccomp(void) {
#ifdef SYS_seccomp
    unsigned int action = SECCOMP_RET_KILL_PROCESS;
    errno = 0;
    long rc = syscall(SYS_seccomp, SECCOMP_GET_ACTION_AVAIL, 0U, &action);
    print_syscall_result("seccomp_get_action_avail", rc, errno);
#else
    puts("INFO security.seccomp_get_action_avail state=unavailable reason=SYS_seccomp-not-defined");
#endif
}

static void probe_keyring(void) {
#ifdef SYS_keyctl
    errno = 0;
    long rc = syscall(SYS_keyctl, KEYCTL_GET_KEYRING_ID, KEY_SPEC_PROCESS_KEYRING, 0);
    print_syscall_result("keyctl_get_process_keyring", rc, errno);
#else
    puts("INFO security.keyctl_get_process_keyring state=unavailable reason=SYS_keyctl-not-defined");
#endif
}

static void probe_audit(void) {
    errno = 0;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_AUDIT);
    if (fd >= 0) {
        printf("INFO security.audit_netlink_socket state=success value=%d\n", fd);
        close(fd);
    } else {
        printf("INFO security.audit_netlink_socket state=error errno=%d name=%s\n", errno, strerror(errno));
    }
}

static void probe_bpf(void) {
#ifdef SYS_bpf
    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.start_id = 0;
    errno = 0;
    long rc = syscall(SYS_bpf, BPF_PROG_GET_NEXT_ID, &attr, sizeof(attr));
    print_syscall_result("bpf_prog_get_next_id", rc, errno);
#else
    puts("INFO security.bpf_prog_get_next_id state=unavailable reason=SYS_bpf-not-defined");
#endif
}

static void probe_prctl(void) {
    errno = 0;
    long securebits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0);
    print_syscall_result("prctl_get_securebits", securebits, errno);

    errno = 0;
    long nnp = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    print_syscall_result("prctl_get_no_new_privs", nnp, errno);

    errno = 0;
    long seccomp = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
    print_syscall_result("prctl_get_seccomp", seccomp, errno);

    errno = 0;
    long cap = prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN, 0, 0, 0);
    print_syscall_result("prctl_capbset_read_sys_admin", cap, errno);
}

static void probe_namespace_fds(void) {
    static const char *names[] = {"mnt", "pid", "user", "net", "uts", "ipc", "cgroup", "time"};
    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        char path[128];
        snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
        errno = 0;
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            struct stat st;
            int stat_rc = fstat(fd, &st);
            if (stat_rc == 0) {
                printf("INFO namespace.%s state=present inode=%llu\n", names[i], (unsigned long long)st.st_ino);
            } else {
                printf("INFO namespace.%s state=fstat-error errno=%d\n", names[i], errno);
            }
            close(fd);
        } else {
            printf("INFO namespace.%s state=absent errno=%d\n", names[i], errno);
        }
    }
}

int main(void) {
    probe_prctl();
    probe_seccomp();
    probe_keyring();
    probe_audit();
    probe_bpf();
    probe_namespace_fds();
    puts("PASS step36.security-api-probe.complete");
    return 0;
}
