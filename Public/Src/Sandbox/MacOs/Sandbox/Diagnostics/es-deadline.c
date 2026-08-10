// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Establishes what a slow Endpoint Security handler actually costs.
//
// The broker sets ES_DEADLINE_MISS_MODE_FAIL_OPEN because the default is to kill the client, and a
// dead client mid-pip would destroy the whole event stream with no way to tell how much was lost.
// That the setting is accepted proves nothing about what happens when a deadline is actually
// missed. The two possible outcomes are very different for soundness:
//
//   the client survives and messages are dropped   detectable, because global_seq_num gaps
//   the client is killed                           also detectable, but the pip cannot continue
//
// Either is safe as long as it is visible. Silently continuing with a complete-looking sequence
// would not be, and that is what this rules out.
//
// Build:
//   clang -o es-deadline Diagnostics/es-deadline.c -lEndpointSecurity -lbsm
// Sign (SIP/AMFI relaxed, or a real provisioned entitlement):
//   codesign --force --sign - --entitlements <ent.plist> es-deadline
// Run:
//   ./es-deadline [handler-delay-microseconds]

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static atomic_ullong g_seen = 0;
static atomic_ullong g_gapped = 0;
static atomic_ullong g_lastSequence = 0;
static atomic_ullong g_afterSlow = 0;
static atomic_int g_slowing = 0;

int main(int argc, char **argv)
{
    const useconds_t delay = (useconds_t)(argc > 1 ? atoi(argv[1]) : 20000);

    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_descendants_client(&client, ^(es_client_t *c, const es_message_t *message) {
        (void)c;

        const unsigned long long sequence = message->global_seq_num;
        const unsigned long long previous = atomic_exchange(&g_lastSequence, sequence);

        if (previous != 0 && sequence > previous + 1)
        {
            atomic_fetch_add(&g_gapped, sequence - previous - 1);
        }

        atomic_fetch_add(&g_seen, 1);

        if (atomic_load(&g_slowing))
        {
            atomic_fetch_add(&g_afterSlow, 1);
            // Deliberately blow past any reasonable deadline.
            usleep(delay);
        }
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
    {
        printf("es_new_descendants_client failed = %d\n", result);
        return 1;
    }

    if (es_set_deadline_miss_mode(client, ES_DEADLINE_MISS_MODE_FAIL_OPEN) != ES_RETURN_SUCCESS)
    {
        printf("es_set_deadline_miss_mode failed\n");
        return 1;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_EXEC,  ES_EVENT_TYPE_NOTIFY_FORK,   ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_OPEN,  ES_EVENT_TYPE_NOTIFY_CLOSE,  ES_EVENT_TYPE_NOTIFY_STAT,
        ES_EVENT_TYPE_NOTIFY_LOOKUP,
    };

    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS)
    {
        printf("es_subscribe failed\n");
        return 1;
    }

    // A warm-up pass at full speed establishes that the client works at all, so a later silence can
    // be attributed to the delay rather than to the client never having been live.
    system("/bin/sh -c '/bin/ls /usr/bin >/dev/null'");
    sleep(1);

    const unsigned long long baseline = atomic_load(&g_seen);
    const unsigned long long baselineGaps = atomic_load(&g_gapped);

    // The same workload is run twice, once with a fast handler and once with a slow one. If the
    // kernel drops messages under pressure the two should take the same time and the slow arm should
    // gap; if it throttles the producer instead, the slow arm should take longer and not gap. That
    // distinction is the whole question, and only a paired timing can tell them apart.
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    system("/bin/sh -c 'for i in 1 2 3 4 5 6; do (/usr/bin/find /usr/include -type f >/dev/null 2>&1) & done; wait'");
    clock_gettime(CLOCK_MONOTONIC, &b);
    const double fastSeconds = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
    sleep(1);
    const unsigned long long fastEvents = atomic_load(&g_seen) - baseline;

    atomic_store(&g_slowing, 1);
    clock_gettime(CLOCK_MONOTONIC, &a);
    system("/bin/sh -c 'for i in 1 2 3 4 5 6; do (/usr/bin/find /usr/include -type f >/dev/null 2>&1) & done; wait'");
    clock_gettime(CLOCK_MONOTONIC, &b);
    const double slowSeconds = (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
    sleep(2);
    atomic_store(&g_slowing, 0);
    printf("WORKLOAD_FAST_HANDLER_S=%.2f WORKLOAD_SLOW_HANDLER_S=%.2f THROTTLE_RATIO=%.1f\n",
           fastSeconds, slowSeconds, slowSeconds / fastSeconds);
    printf("FAST_PHASE_EVENTS=%llu SLOW_PHASE_ONLY_EVENTS=%llu\n", fastEvents, atomic_load(&g_afterSlow));

    const unsigned long long total = atomic_load(&g_seen);
    const unsigned long long gaps = atomic_load(&g_gapped);

    // If the client had been killed, nothing would have arrived during the slow phase at all.
    printf("HANDLER_DELAY_US=%u\n", delay);
    printf("WARMUP_EVENTS=%llu WARMUP_GAPS=%llu\n", baseline, baselineGaps);
    printf("SLOW_PHASE_EVENTS=%llu SLOW_PHASE_GAPS=%llu\n", total - baseline, gaps - baselineGaps);
    printf("CLIENT_SURVIVED=%d\n", (total - baseline) > 0 ? 1 : 0);

    // A client killed by the kernel makes further calls fail, which is the direct check.
    const es_return_t stillAlive = es_unsubscribe_all(client);
    printf("UNSUBSCRIBE_AFTER_SLOW=%s\n", stillAlive == ES_RETURN_SUCCESS ? "SUCCESS" : "ERROR");

    es_delete_client(client);
    return 0;
}
