// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Records what a real build tool actually delegates, so the broker's delegation policy can be
// designed against evidence instead of intuition.
//
// The broker treats XPC connects, bootstrap lookups and UNIX-domain socket connects as
// "delegation": a process handing work to a service outside the descendant domain, whose file
// accesses the broker therefore cannot see. Classified that way, a real compile taints and no
// macOS pip is ever cacheable - which makes the sandbox worthless however correct it is.
//
// Before narrowing that rule, it is worth knowing what is actually being contacted. This subscribes
// a descendants client to the three delegation event types, runs a workload, and prints every
// distinct (event type, actor, target) it saw with a count.
//
// Build:
//   clang -o es-delegation Diagnostics/es-delegation.c -lEndpointSecurity -lbsm
// Sign (SIP/AMFI relaxed, or a real provisioned entitlement):
//   codesign --force --sign - --entitlements <ent.plist> es-delegation
// Run:
//   ./es-delegation '<shell command>'

#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_ROWS 512
#define MAX_TEXT 256

struct Row
{
    char kind[24];
    char actor[MAX_TEXT];
    char target[MAX_TEXT];
    unsigned long long count;
    int actorIsPlatform;
};

static struct Row g_rows[MAX_ROWS];
static int g_rowCount = 0;
static unsigned long long g_total = 0;
static dispatch_queue_t g_queue;

static void CopyToken(char *out, size_t cap, const char *data, size_t length)
{
    if (data == NULL)
    {
        snprintf(out, cap, "(null)");
        return;
    }

    size_t copy = length < cap - 1 ? length : cap - 1;
    memcpy(out, data, copy);
    out[copy] = '\0';
}

// Called on a serial queue, so no locking is needed.
static void Record(const char *kind, const char *actor, int actorIsPlatform, const char *target)
{
    g_total++;

    for (int i = 0; i < g_rowCount; i++)
    {
        if (strcmp(g_rows[i].kind, kind) == 0 &&
            strcmp(g_rows[i].actor, actor) == 0 &&
            strcmp(g_rows[i].target, target) == 0)
        {
            g_rows[i].count++;
            return;
        }
    }

    if (g_rowCount >= MAX_ROWS)
    {
        return;
    }

    struct Row *row = &g_rows[g_rowCount++];
    snprintf(row->kind, sizeof(row->kind), "%s", kind);
    snprintf(row->actor, sizeof(row->actor), "%s", actor);
    snprintf(row->target, sizeof(row->target), "%s", target);
    row->actorIsPlatform = actorIsPlatform;
    row->count = 1;
}

int main(int argc, char **argv)
{
    const char *command = argc > 1 ? argv[1] : "/bin/sh -c 'true'";

    g_queue = dispatch_queue_create("es-delegation", DISPATCH_QUEUE_SERIAL);

    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_descendants_client(&client, ^(es_client_t *c, const es_message_t *message) {
        (void)c;

        // The message is only valid for the duration of the handler, so everything needed is copied
        // out before hopping to the serial queue.
        char actor[MAX_TEXT];
        char target[MAX_TEXT];
        char kind[24];
        int platform = message->process->is_platform_binary ? 1 : 0;

        CopyToken(actor, sizeof(actor),
                  message->process->executable->path.data,
                  message->process->executable->path.length);
        snprintf(target, sizeof(target), "(none)");

        switch (message->event_type)
        {
            case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
                snprintf(kind, sizeof(kind), "xpc-connect");
                CopyToken(target, sizeof(target),
                          message->event.xpc_connect->service_name.data,
                          message->event.xpc_connect->service_name.length);
                break;

            case ES_EVENT_TYPE_NOTIFY_BOOTSTRAP_LOOK_UP:
                snprintf(kind, sizeof(kind), "bootstrap-lookup");
                CopyToken(target, sizeof(target),
                          message->event.bootstrap_look_up->service_name.data,
                          message->event.bootstrap_look_up->service_name.length);
                // The enclosing message describes launchd, which submits this event on the caller's
                // behalf. The header is explicit: "es_message_t.process describes launchd, not the
                // process that called bootstrap_look_up()". The instigator is the actor.
                if (message->event.bootstrap_look_up->instigator != NULL)
                {
                    CopyToken(actor, sizeof(actor),
                              message->event.bootstrap_look_up->instigator->executable->path.data,
                              message->event.bootstrap_look_up->instigator->executable->path.length);
                    platform = message->event.bootstrap_look_up->instigator->is_platform_binary ? 1 : 0;
                }
                else
                {
                    snprintf(actor, sizeof(actor), "(instigator exited)");
                }
                break;

            case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
                snprintf(kind, sizeof(kind), "uipc-connect");
                if (message->event.uipc_connect.file != NULL)
                {
                    CopyToken(target, sizeof(target),
                              message->event.uipc_connect.file->path.data,
                              message->event.uipc_connect.file->path.length);
                }
                break;

            default:
                return;
        }

        char *kindCopy = strdup(kind);
        char *actorCopy = strdup(actor);
        char *targetCopy = strdup(target);
        dispatch_async(g_queue, ^{
            Record(kindCopy, actorCopy, platform, targetCopy);
            free(kindCopy);
            free(actorCopy);
            free(targetCopy);
        });
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
    {
        printf("es_new_descendants_client failed = %d\n", result);
        return 1;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
        ES_EVENT_TYPE_NOTIFY_BOOTSTRAP_LOOK_UP,
        ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
    };

    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS)
    {
        printf("es_subscribe failed\n");
        return 1;
    }

    int rc = system(command);
    sleep(2);
    es_unsubscribe_all(client);

    // Drain the serial queue so nothing recorded is missed.
    dispatch_sync(g_queue, ^{});

    printf("COMMAND_RC=%d TOTAL_DELEGATION_EVENTS=%llu DISTINCT=%d\n", rc, g_total, g_rowCount);
    for (int i = 0; i < g_rowCount; i++)
    {
        printf("  %-17s %6llu  platform=%d  target=%-46s actor=%s\n",
               g_rows[i].kind, g_rows[i].count, g_rows[i].actorIsPlatform,
               g_rows[i].target, g_rows[i].actor);
    }

    es_delete_client(client);
    return 0;
}
