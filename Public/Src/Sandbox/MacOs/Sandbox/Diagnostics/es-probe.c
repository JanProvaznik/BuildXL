// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * es-probe - the smallest program that proves Endpoint Security actually works on this machine.
 *
 * The broker's own test suite drives ReplaySource, so it proves the protocol and says nothing about
 * the kernel. This says something about the kernel and nothing about the protocol, which is exactly
 * the gap the missing entitlement leaves (see MacOsSandbox.md 4.4).
 *
 * It creates a descendants client, subscribes, spawns a child that touches a file whose path only
 * this run knows, and reports whether the event arrived. Every stage is reported separately so a
 * failure names the thing that failed rather than "it didn't work".
 *
 *   stage 1  client created          -> the entitlement is present and honoured
 *   stage 2  deadline mode accepted  -> macOS 27 deadline control is available
 *   stage 3  subscription accepted   -> every event type in the set is valid on this OS
 *   stage 4  child event observed    -> descendant scoping delivers real file accesses
 *
 * Build and run through es-check.sh, which handles signing. Building it by hand is fine too:
 *   clang -isysroot "$(xcrun --show-sdk-path)" -lEndpointSecurity -o es-probe es-probe.c
 */

#include <errno.h>
#include <limits.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#if !__has_include(<EndpointSecurity/EndpointSecurity.h>)
int main(void)
{
    fprintf(stderr, "es-probe: no EndpointSecurity SDK. Install the macOS 27 SDK and rebuild.\n");
    return 2;
}
#else

#include <EndpointSecurity/EndpointSecurity.h>

extern char **environ;

static const char *ClientResultName(es_new_client_result_t r)
{
    switch (r)
    {
        case ES_NEW_CLIENT_RESULT_SUCCESS:              return "SUCCESS";
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "ERR_INVALID_ARGUMENT";
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:         return "ERR_INTERNAL";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:     return "ERR_NOT_ENTITLED";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:    return "ERR_NOT_PERMITTED";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:   return "ERR_NOT_PRIVILEGED";
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return "ERR_TOO_MANY_CLIENTS";
        default:                                        return "UNKNOWN";
    }
}

static void ExplainClientFailure(es_new_client_result_t r)
{
    switch (r)
    {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:
            fprintf(stderr,
                "  The binary is not signed with com.apple.developer.endpoint-security.client, or it is\n"
                "  signed with it but AMFI is enforcing and the signature is not backed by a profile\n"
                "  that authorizes the entitlement. es-check.sh prints the two ways to fix this.\n");
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:
            fprintf(stderr,
                "  Entitlement present but TCC denied. es_new_descendants_client is documented as not\n"
                "  requiring TCC, so seeing this is worth reporting: it suggests a fallback to\n"
                "  es_new_client, which does require Full Disk Access.\n");
            break;
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:
            fprintf(stderr, "  Needs root. Re-run under sudo.\n");
            break;
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:
            fprintf(stderr,
                "  The system-wide Endpoint Security client budget is exhausted. This is the failure\n"
                "  mode MacOsSandbox.md 4.4 flags as the main open risk for concurrent pips.\n");
            break;
        default:
            break;
    }
}

/* Only what the probe needs. The broker's real set is EsIngress::SubscriptionSet. */
static const es_event_type_t kProbeEvents[] = {
    ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_FORK,
    ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_NOTIFY_OPEN,
    ES_EVENT_TYPE_NOTIFY_CLOSE,
    ES_EVENT_TYPE_NOTIFY_CREATE,
    ES_EVENT_TYPE_NOTIFY_LOOKUP,
    ES_EVENT_TYPE_NOTIFY_STAT,
};

static char g_needle[PATH_MAX];
static _Atomic int g_sawMarker = 0;
static _Atomic int g_sawExec = 0;
static _Atomic unsigned long g_total = 0;

static const char *EventPath(const es_message_t *m)
{
    switch (m->event_type)
    {
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            return m->event.open.file->path.data;
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            return m->event.close.target->path.data;
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            return m->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE
                ? m->event.create.destination.existing_file->path.data
                : m->event.create.destination.new_path.filename.data;
        case ES_EVENT_TYPE_NOTIFY_LOOKUP:
            return m->event.lookup.relative_target.data;
        case ES_EVENT_TYPE_NOTIFY_STAT:
            return m->event.stat.target->path.data;
        default:
            return NULL;
    }
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    snprintf(g_needle, sizeof(g_needle), "/tmp/bxl-es-probe-%d-%ld.marker",
             (int)getpid(), (long)time(NULL));

    printf("es-probe: descendant-scoped Endpoint Security check\n");
    printf("  marker: %s\n\n", g_needle);

    /* ---- stage 1: client ---- */
    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_descendants_client(&client,
        ^(es_client_t *c, const es_message_t *m)
    {
        (void)c;
        atomic_fetch_add(&g_total, 1);

        if (m->event_type == ES_EVENT_TYPE_NOTIFY_EXEC)
        {
            atomic_store(&g_sawExec, 1);
            return;
        }

        const char *p = EventPath(m);
        if (p != NULL && strstr(p, "bxl-es-probe-") != NULL)
        {
            atomic_store(&g_sawMarker, 1);
        }
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
    {
        printf("stage 1  client created ......... FAIL (%s)\n", ClientResultName(result));
        ExplainClientFailure(result);
        return 1;
    }
    printf("stage 1  client created ......... ok\n");

    /* ---- stage 2: deadline control, macOS 27 only ---- */
    if (es_set_deadline_miss_mode(client, ES_DEADLINE_MISS_MODE_FAIL_OPEN) != ES_RETURN_SUCCESS)
    {
        printf("stage 2  deadline mode .......... FAIL (es_set_deadline_miss_mode rejected)\n");
        fprintf(stderr,
            "  The broker relies on FAIL_OPEN so a missed deadline becomes a sequence gap and a\n"
            "  taint rather than a dead client. The default is KILL.\n");
        es_delete_client(client);
        return 1;
    }
    printf("stage 2  deadline mode .......... ok (FAIL_OPEN accepted)\n");

    /* ---- stage 3: subscription ---- */
    const uint32_t count = (uint32_t)(sizeof(kProbeEvents) / sizeof(kProbeEvents[0]));
    if (es_subscribe(client, kProbeEvents, count) != ES_RETURN_SUCCESS)
    {
        printf("stage 3  subscription ........... FAIL (es_subscribe rejected %u events)\n", count);
        es_delete_client(client);
        return 1;
    }
    printf("stage 3  subscription ........... ok (%u event types)\n", count);

    /* ---- stage 4: observe a real descendant ---- */
    char script[PATH_MAX + 64];
    snprintf(script, sizeof(script), "printf x > '%s'; cat '%s' > /dev/null", g_needle, g_needle);

    char *argv[] = { (char *)"/bin/sh", (char *)"-c", script, NULL };
    pid_t child = 0;
    int rc = posix_spawn(&child, "/bin/sh", NULL, NULL, argv, environ);
    if (rc != 0)
    {
        printf("stage 4  child observed ......... FAIL (posix_spawn: %s)\n", strerror(rc));
        es_delete_client(client);
        return 1;
    }

    int status = 0;
    waitpid(child, &status, 0);

    /* Delivery is asynchronous; give it a bounded moment. */
    for (int i = 0; i < 200 && !atomic_load(&g_sawMarker); i++)
    {
        usleep(10 * 1000);
    }

    const int sawMarker = atomic_load(&g_sawMarker);
    const int sawExec = atomic_load(&g_sawExec);
    const unsigned long total = atomic_load(&g_total);

    printf("stage 4  child observed ......... %s\n", sawMarker ? "ok" : "FAIL");
    printf("\n  events delivered: %lu   exec seen: %s   marker access seen: %s\n",
           total, sawExec ? "yes" : "no", sawMarker ? "yes" : "no");

    unlink(g_needle);
    es_unsubscribe_all(client);
    es_delete_client(client);

    if (!sawMarker)
    {
        fprintf(stderr,
            "\n  Client created and subscribed, but no access to the marker arrived. /bin/sh is a\n"
            "  platform binary, so this is also the exact case dyld interposition cannot cover,\n"
            "  which is the whole reason the kernel backend exists.\n");
        return 1;
    }

    printf("\nes-probe: PASS - Endpoint Security is usable on this machine.\n");
    return 0;
}

#endif /* __has_include(<EndpointSecurity/EndpointSecurity.h>) */
