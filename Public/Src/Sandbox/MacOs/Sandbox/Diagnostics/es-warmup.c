// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Measures how long an Endpoint Security client takes to become *useful*, as distinct from how long
// it takes to create.
//
// es-budget.c already showed that es_new_descendants_client plus es_subscribe costs about 155 us.
// That is the wrong number for judging a design that starts one broker per pip, because what a pip
// actually waits for is the first event to come back - the broker emits a marker and cannot let the
// tool start until it has observed its own marker, which is what proves observation is live.
//
// The gap between those two numbers turned out to be three orders of magnitude, and it is the
// dominant fixed cost of the Endpoint Security backend.
//
// Build:
//   clang -o es-warmup Diagnostics/es-warmup.c -lEndpointSecurity -lbsm
// Sign, then:
//   ./es-warmup [iterations]

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

static uint64_t NowNanos(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int CompareU64(const void *a, const void *b)
{
    const uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : (x > y ? 1 : 0);
}

int main(int argc, char **argv)
{
    const int iterations = argc > 1 ? atoi(argv[1]) : 20;
    const char *markerStyle = argc > 2 ? argv[2] : "open-create";

    uint64_t *createNanos = calloc((size_t)iterations, sizeof(uint64_t));
    uint64_t *firstEventNanos = calloc((size_t)iterations, sizeof(uint64_t));
    uint64_t *emissionCounts = calloc((size_t)iterations, sizeof(uint64_t));

    for (int i = 0; i < iterations; i++)
    {
        __block atomic_ullong firstSeen = 0;

        const uint64_t beforeCreate = NowNanos();

        es_client_t *client = NULL;
        es_new_client_result_t result = es_new_descendants_client(&client, ^(es_client_t *c, const es_message_t *m) {
            (void)c;
            (void)m;
            uint64_t expected = 0;
            atomic_compare_exchange_strong(&firstSeen, &expected, NowNanos());
        });

        if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
        {
            printf("es_new_descendants_client failed = %d\n", result);
            return 1;
        }

        es_event_type_t events[] = { ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_STAT,
                                     ES_EVENT_TYPE_NOTIFY_LOOKUP, ES_EVENT_TYPE_NOTIFY_EXEC };
        if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS)
        {
            printf("es_subscribe failed\n");
            return 1;
        }

        const uint64_t afterSubscribe = NowNanos();
        createNanos[i] = afterSubscribe - beforeCreate;

        // This is the broker's marker: a filesystem touch by this very process, which a descendants
        // client must see. Retried in a tight loop because the point is to find when the stream
        // starts delivering, not to measure one syscall.
        char path[256];
        snprintf(path, sizeof path, "/tmp/es-warmup-%d-%d", (int)getpid(), i);

        // Emitted once, exactly as the broker does it, because the question is how long the kernel
        // takes to deliver one marker - not how long a retry loop takes to get lucky.
        if (strcmp(markerStyle, "stat-missing") == 0)
        {
            struct stat sb;
            (void)stat(path, &sb);
        }
        else
        {
            int fd = open(path, O_CREAT | O_RDWR, 0600);
            if (fd >= 0) { close(fd); }
        }

        unsigned long emissions = 1;
        while (atomic_load(&firstSeen) == 0)
        {
            if (NowNanos() - afterSubscribe > 5000000000ull) { break; }

            if (strcmp(markerStyle, "burst") == 0)
            {
                struct stat sb;
                (void)stat(path, &sb);
                emissions++;
            }
            else
            {
                usleep(50);
            }
        }
        emissionCounts[i] = emissions;

        const uint64_t seen = atomic_load(&firstSeen);
        firstEventNanos[i] = seen == 0 ? 0 : seen - afterSubscribe;

        unlink(path);
        es_delete_client(client);
    }

    qsort(createNanos, (size_t)iterations, sizeof(uint64_t), CompareU64);
    qsort(firstEventNanos, (size_t)iterations, sizeof(uint64_t), CompareU64);

    printf("ITERATIONS=%d\n", iterations);
    printf("CREATE_AND_SUBSCRIBE_US p50=%llu p95=%llu max=%llu\n",
           createNanos[iterations / 2] / 1000,
           createNanos[(iterations * 95) / 100] / 1000,
           createNanos[iterations - 1] / 1000);
    printf("MARKER_STYLE=%s\n", markerStyle);
    printf("FIRST_EVENT_AFTER_SUBSCRIBE_US p50=%llu p95=%llu max=%llu\n",
           firstEventNanos[iterations / 2] / 1000,
           firstEventNanos[(iterations * 95) / 100] / 1000,
           firstEventNanos[iterations - 1] / 1000);

    qsort(emissionCounts, (size_t)iterations, sizeof(uint64_t), CompareU64);
    printf("MARKER_EMISSIONS_BEFORE_FIRST_EVENT p50=%llu max=%llu\n", emissionCounts[iterations/2], emissionCounts[iterations-1]);
    free(emissionCounts);
    free(createNanos);
    free(firstEventNanos);
    return 0;
}
