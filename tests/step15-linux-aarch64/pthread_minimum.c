// SPDX-License-Identifier: LicenseRef-Qyronex-Kernal-NC-1.0
#define _GNU_SOURCE

#include <pthread.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

static _Thread_local unsigned long tls_cookie = 0x1122334455667788UL;
static unsigned long worker_tls_observed;

static int valid_timespec(const struct timespec *value)
{
    return value->tv_sec >= 0 && value->tv_nsec >= 0 && value->tv_nsec < 1000000000L;
}

static void *worker(void *argument)
{
    (void)argument;

    if (tls_cookie != 0x1122334455667788UL)
        return (void *)(uintptr_t)1;

    tls_cookie = 0x8877665544332211UL;
    worker_tls_observed = tls_cookie;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0 || !valid_timespec(&now))
        return (void *)(uintptr_t)2;

    unsigned char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (page == MAP_FAILED)
        return (void *)(uintptr_t)3;

    page[0] = 0x5a;
    page[4095] = 0xa5;
    if (page[0] != 0x5a || page[4095] != 0xa5) {
        (void)munmap(page, 4096);
        return (void *)(uintptr_t)4;
    }

    if (munmap(page, 4096) != 0)
        return (void *)(uintptr_t)5;

    return NULL;
}

int main(void)
{
    /* musl deliberately supports only the non-mutating sbrk(0) query. */
    if (sbrk(0) == (void *)-1)
        return 10;

    struct timespec before;
    if (clock_gettime(CLOCK_MONOTONIC, &before) != 0 || !valid_timespec(&before))
        return 11;

    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0)
        return 12;

    /* Keep the minimum Step-15 contract honest: no guard-page mprotect dependency. */
    if (pthread_attr_setguardsize(&attr, 0) != 0) {
        (void)pthread_attr_destroy(&attr);
        return 13;
    }

    tls_cookie = 0xa1a2a3a4a5a6a7a8UL;

    pthread_t thread;
    if (pthread_create(&thread, &attr, worker, NULL) != 0) {
        (void)pthread_attr_destroy(&attr);
        return 14;
    }
    (void)pthread_attr_destroy(&attr);

    void *thread_result = NULL;
    if (pthread_join(thread, &thread_result) != 0)
        return 15;
    if (thread_result != NULL)
        return 16 + (int)(uintptr_t)thread_result;

    if (worker_tls_observed != 0x8877665544332211UL)
        return 22;
    if (tls_cookie != 0xa1a2a3a4a5a6a7a8UL)
        return 23;

    struct timespec after;
    if (clock_gettime(CLOCK_MONOTONIC, &after) != 0 || !valid_timespec(&after))
        return 24;
    if (after.tv_sec < before.tv_sec ||
        (after.tv_sec == before.tv_sec && after.tv_nsec < before.tv_nsec))
        return 25;

    static const char marker[] = "KERNAL/S15: unchanged musl pthread minimum passed\n";
    if (write(STDOUT_FILENO, marker, sizeof(marker) - 1) != (ssize_t)(sizeof(marker) - 1))
        return 26;

    return 0;
}
