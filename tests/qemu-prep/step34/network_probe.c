#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>
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

static int parse_port(const char *value, int fallback, const char *name) {
    if (value == NULL || *value == '\0') {
        return fallback;
    }
    char *end = NULL;
    long parsed = strtol(value, &end, 10);
    if (end == NULL || *end != '\0' || parsed < 1 || parsed > 65535) {
        fprintf(stderr, "FAIL %s invalid-port=%s\n", name, value);
        exit(1);
    }
    return (int)parsed;
}

static void set_recv_timeout(int fd) {
    struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
        fail("socket.recv-timeout");
    }
}

static void test_unix_stream(void) {
    char path[sizeof(((struct sockaddr_un *)0)->sun_path)];
    snprintf(path, sizeof(path), "/tmp/kernal-net-probe-%ld.sock", (long)getpid());
    unlink(path);

    int server = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) {
        fail("unix.server-socket");
    }
    struct sockaddr_un address;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s", path) >= (int)sizeof(address.sun_path)) {
        errno = ENAMETOOLONG;
        fail("unix.path-length");
    }
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fail("unix.bind");
    }
    if (listen(server, 4) != 0) {
        fail("unix.listen");
    }

    pid_t child = fork();
    if (child < 0) {
        fail("unix.fork");
    }
    if (child == 0) {
        int client = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (client < 0) {
            _exit(101);
        }
        if (connect(client, (struct sockaddr *)&address, sizeof(address)) != 0) {
            _exit(102);
        }
        if (send(client, "unix-ping", 9, 0) != 9) {
            _exit(103);
        }
        char reply[32] = {0};
        ssize_t got = recv(client, reply, sizeof(reply) - 1, 0);
        if (got != 7 || memcmp(reply, "unix-ok", 7) != 0) {
            _exit(104);
        }
        close(client);
        _exit(0);
    }

    int peer = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    if (peer < 0) {
        fail("unix.accept");
    }
    char request[32] = {0};
    ssize_t got = recv(peer, request, sizeof(request) - 1, 0);
    require_true(got == 9 && memcmp(request, "unix-ping", 9) == 0, "unix.stream-receive");
    require_true(send(peer, "unix-ok", 7, 0) == 7, "unix.stream-reply");
    close(peer);
    close(server);

    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        fail("unix.waitpid");
    }
    require_true(WIFEXITED(status) && WEXITSTATUS(status) == 0, "unix.stream-child-exit");
    if (unlink(path) != 0) {
        fail("unix.unlink-path");
    }
}

static void test_ipv6_loopback(void) {
    int server = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (server < 0) {
        fail("ipv6.server-socket");
    }
    int v6only = -1;
    socklen_t optlen = sizeof(v6only);
    if (getsockopt(server, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &optlen) != 0) {
        fail("ipv6.get-v6only");
    }
    printf("INFO ipv6.v6only-default=%d\n", v6only);

    struct sockaddr_in6 address;
    memset(&address, 0, sizeof(address));
    address.sin6_family = AF_INET6;
    address.sin6_addr = in6addr_loopback;
    address.sin6_port = 0;
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) != 0) {
        fail("ipv6.bind-loopback");
    }
    if (listen(server, 2) != 0) {
        fail("ipv6.listen");
    }
    socklen_t address_len = sizeof(address);
    if (getsockname(server, (struct sockaddr *)&address, &address_len) != 0) {
        fail("ipv6.getsockname");
    }

    pid_t child = fork();
    if (child < 0) {
        fail("ipv6.fork");
    }
    if (child == 0) {
        int client = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (client < 0) {
            _exit(111);
        }
        if (connect(client, (struct sockaddr *)&address, sizeof(address)) != 0) {
            _exit(112);
        }
        if (send(client, "v6-ping", 7, 0) != 7) {
            _exit(113);
        }
        char reply[16] = {0};
        ssize_t read_count = recv(client, reply, sizeof(reply), 0);
        close(client);
        if (read_count != 5 || memcmp(reply, "v6-ok", 5) != 0) {
            _exit(114);
        }
        _exit(0);
    }

    int peer = accept4(server, NULL, NULL, SOCK_CLOEXEC);
    if (peer < 0) {
        fail("ipv6.accept");
    }
    char request[16] = {0};
    ssize_t got = recv(peer, request, sizeof(request), 0);
    require_true(got == 7 && memcmp(request, "v6-ping", 7) == 0, "ipv6.loopback-receive");
    require_true(send(peer, "v6-ok", 5, 0) == 5, "ipv6.loopback-reply");
    close(peer);
    close(server);

    int status = 0;
    if (waitpid(child, &status, 0) != child) {
        fail("ipv6.waitpid");
    }
    require_true(WIFEXITED(status) && WEXITSTATUS(status) == 0, "ipv6.loopback-child-exit");
}

static struct sockaddr_in ipv4_target(const char *host, int port, const char *name) {
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, host, &address.sin_addr) != 1) {
        fprintf(stderr, "FAIL %s invalid-ipv4=%s\n", name, host);
        exit(1);
    }
    return address;
}

static void test_tcp(void) {
    const char *host = getenv("KERNAL_TCP_HOST");
    if (host == NULL || *host == '\0') {
        host = "10.0.2.2";
    }
    int port = parse_port(getenv("KERNAL_TCP_PORT"), 18081, "tcp.port");
    struct sockaddr_in target = ipv4_target(host, port, "tcp.host");

    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fail("tcp.socket");
    }
    set_recv_timeout(fd);
    if (connect(fd, (struct sockaddr *)&target, sizeof(target)) != 0) {
        fail("tcp.connect");
    }
    require_true(send(fd, "tcp-ping", 8, 0) == 8, "tcp.send");
    char reply[64] = {0};
    ssize_t got = recv(fd, reply, sizeof(reply) - 1, 0);
    require_true(got > 0 && strstr(reply, "KERNAL_TCP_OK") != NULL, "tcp.host-endpoint-reply");
    close(fd);
}

static void test_udp(void) {
    const char *host = getenv("KERNAL_UDP_HOST");
    if (host == NULL || *host == '\0') {
        host = "10.0.2.2";
    }
    int port = parse_port(getenv("KERNAL_UDP_PORT"), 18082, "udp.port");
    struct sockaddr_in target = ipv4_target(host, port, "udp.host");

    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        fail("udp.socket");
    }
    set_recv_timeout(fd);
    const char *request = "udp-ping";
    ssize_t sent = sendto(fd, request, strlen(request), 0, (struct sockaddr *)&target, sizeof(target));
    require_true(sent == (ssize_t)strlen(request), "udp.sendto");
    char reply[128] = {0};
    ssize_t got = recvfrom(fd, reply, sizeof(reply) - 1, 0, NULL, NULL);
    require_true(got > 0 && strstr(reply, "KERNAL_UDP_OK:udp-ping") != NULL, "udp.host-endpoint-reply");
    close(fd);
}

static void observe_malformed_netlink_route(void) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        fail("netlink.socket");
    }
    set_recv_timeout(fd);
    struct sockaddr_nl kernel;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;

    struct nlmsghdr request;
    memset(&request, 0, sizeof(request));
    request.nlmsg_len = sizeof(request) - 1;
    request.nlmsg_type = RTM_GETLINK;
    request.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.nlmsg_seq = 1;

    errno = 0;
    ssize_t sent = sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&kernel, sizeof(kernel));
    if (sent < 0) {
        printf("INFO netlink.malformed state=send-error errno=%d\n", errno);
        close(fd);
        return;
    }

    unsigned char response[4096];
    errno = 0;
    ssize_t got = recv(fd, response, sizeof(response), 0);
    if (got < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            puts("INFO netlink.malformed state=no-reply");
            close(fd);
            return;
        }
        fail("netlink.recv-malformed-result");
    }
    if ((size_t)got >= sizeof(struct nlmsghdr)) {
        const struct nlmsghdr *header = (const struct nlmsghdr *)response;
        if (header->nlmsg_type == NLMSG_ERROR && (size_t)got >= NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
            const struct nlmsgerr *error = (const struct nlmsgerr *)NLMSG_DATA(header);
            printf("INFO netlink.malformed state=nlmsg-error error=%d\n", error->error);
        } else {
            printf("INFO netlink.malformed state=reply type=%u bytes=%zd\n", header->nlmsg_type, got);
        }
    } else {
        printf("INFO netlink.malformed state=short-reply bytes=%zd\n", got);
    }
    close(fd);
}

static void test_dns_if_requested(void) {
    const char *name = getenv("KERNAL_DNS_NAME");
    if (name == NULL || *name == '\0') {
        puts("SKIP dns.lookup reason=KERNAL_DNS_NAME-not-set");
        return;
    }
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *result = NULL;
    int rc = getaddrinfo(name, NULL, &hints, &result);
    if (rc != 0) {
        fprintf(stderr, "FAIL dns.getaddrinfo name=%s gai=%d (%s)\n", name, rc, gai_strerror(rc));
        exit(1);
    }
    int count = 0;
    for (struct addrinfo *item = result; item != NULL; item = item->ai_next) {
        char host[NI_MAXHOST];
        int name_rc = getnameinfo(item->ai_addr, item->ai_addrlen, host, sizeof(host), NULL, 0, NI_NUMERICHOST);
        if (name_rc == 0) {
            printf("INFO dns.address family=%d value=%s\n", item->ai_family, host);
            count++;
        }
    }
    freeaddrinfo(result);
    require_true(count > 0, "dns.lookup");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    test_unix_stream();
    test_ipv6_loopback();
    observe_malformed_netlink_route();
    test_tcp();
    test_udp();
    test_dns_if_requested();
    puts("PASS step34.network-probe.complete");
    return 0;
}
