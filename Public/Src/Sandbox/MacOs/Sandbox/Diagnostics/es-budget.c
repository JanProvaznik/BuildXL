// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Measures how many Endpoint Security clients can exist at once.
//
// This is the risk that killed BuildXL's first macOS sandbox. The design here gives each pip its
// own broker process holding one descendants client, so the number of clients the system will grant
// is a hard ceiling on build concurrency. If that ceiling is below the core count of a developer
// machine, the design does not work and no amount of correctness makes up for it.
//
// Two limits are distinguishable and both matter:
//
//   per-process   how many clients one process may hold. Irrelevant to the current design, which
//                 uses one per broker, but it decides whether a single-broker design is possible.
//   system-wide   how many clients may exist across all processes. This is the one that caps
//                 concurrency, because BuildXL runs one broker per concurrently executing pip.
//
// Build:
//   clang -o es-budget Diagnostics/es-budget.c -lEndpointSecurity -lbsm
// Sign (SIP/AMFI relaxed, or a real provisioned entitlement):
//   codesign --force --sign - --entitlements <ent.plist> es-budget
// Run:
//   ./es-budget perprocess [max]
//   ./es-budget systemwide [count]     # forks `count` children, each holding one client
//   ./es-budget churn [iterations]     # create+subscribe+delete repeatedly, report latency
//   ./es-budget child                  # internal: hold one client until told to exit

#include <EndpointSecurity/EndpointSecurity.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static const char *ResultName(es_new_client_result_t result)
{
    switch (result)
    {
        case ES_NEW_CLIENT_RESULT_SUCCESS:              return "SUCCESS";
        case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: return "ERR_INVALID_ARGUMENT";
        case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:         return "ERR_INTERNAL";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:     return "ERR_NOT_ENTITLED";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:    return "ERR_NOT_PERMITTED (TCC)";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:   return "ERR_NOT_PRIVILEGED (root)";
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return "ERR_TOO_MANY_CLIENTS";
        default:                                        return "UNKNOWN";
    }
}

// Subscribing matters: a client that has been created but never subscribed may not be charged the
// same resources as one doing work, and the number that matters is the number of working clients.
static int SubscribeLightly(es_client_t *client)
{
    es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_EXIT};
    return es_subscribe(client, events, sizeof(events) / sizeof(events[0])) == ES_RETURN_SUCCESS;
}

static int RunChild(void)
{
    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_descendants_client(&client, ^(es_client_t *c, const es_message_t *m) {
        (void)c;
        (void)m;
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
    {
        printf("CHILD_FAIL %d %s\n", result, ResultName(result));
        fflush(stdout);
        return 1;
    }

    if (!SubscribeLightly(client))
    {
        printf("CHILD_FAIL_SUBSCRIBE\n");
        fflush(stdout);
        return 1;
    }

    printf("CHILD_OK\n");
    fflush(stdout);

    // Hold the client until the parent takes the process down.
    pause();
    return 0;
}

static int RunPerProcess(int max)
{
    es_client_t **clients = calloc((size_t)max, sizeof(es_client_t *));
    int held = 0;

    for (int i = 0; i < max; i++)
    {
        es_client_t *client = NULL;
        es_new_client_result_t result = es_new_descendants_client(&client, ^(es_client_t *c, const es_message_t *m) {
            (void)c;
            (void)m;
        });

        if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
        {
            printf("per-process limit reached after %d clients: %d %s\n", held, result, ResultName(result));
            break;
        }

        if (!SubscribeLightly(client))
        {
            printf("per-process subscribe failed after %d clients\n", held);
            es_delete_client(client);
            break;
        }

        clients[held++] = client;
    }

    printf("PER_PROCESS_CLIENTS_HELD=%d\n", held);

    for (int i = 0; i < held; i++)
    {
        es_delete_client(clients[i]);
    }

    free(clients);
    return 0;
}

static int RunSystemWide(const char *self, int count)
{
    pid_t *children = calloc((size_t)count, sizeof(pid_t));
    int alive = 0;

    for (int i = 0; i < count; i++)
    {
        int pipeFds[2];
        if (pipe(pipeFds) != 0)
        {
            printf("pipe failed at child %d\n", i);
            break;
        }

        pid_t pid = fork();
        if (pid < 0)
        {
            printf("fork failed at child %d\n", i);
            close(pipeFds[0]);
            close(pipeFds[1]);
            break;
        }

        if (pid == 0)
        {
            close(pipeFds[0]);
            dup2(pipeFds[1], STDOUT_FILENO);
            close(pipeFds[1]);
            // exec rather than run in the fork, so each client is held by a genuinely separate
            // process image - which is what a build does, one broker per pip.
            execl(self, self, "child", (char *)NULL);
            _exit(127);
        }

        close(pipeFds[1]);

        char buffer[128];
        ssize_t got = read(pipeFds[0], buffer, sizeof(buffer) - 1);
        close(pipeFds[0]);

        if (got <= 0)
        {
            printf("child %d produced no answer\n", i);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            break;
        }

        buffer[got] = '\0';
        if (strncmp(buffer, "CHILD_OK", 8) != 0)
        {
            printf("client %d refused: %s", alive, buffer);
            kill(pid, SIGKILL);
            waitpid(pid, NULL, 0);
            break;
        }

        children[alive++] = pid;
    }

    printf("SYSTEM_WIDE_CONCURRENT_CLIENTS=%d\n", alive);

    for (int i = 0; i < alive; i++)
    {
        kill(children[i], SIGKILL);
        waitpid(children[i], NULL, 0);
    }

    free(children);
    return 0;
}

static int RunChurn(int iterations)
{
    // The ceiling is only half the question. BuildXL creates one broker per pip and pips are short,
    // so if creating and tearing down a client is expensive the cost is paid hundreds of times in a
    // build even when the ceiling is never approached.
    uint64_t *createNanos = calloc((size_t)iterations, sizeof(uint64_t));
    uint64_t *deleteNanos = calloc((size_t)iterations, sizeof(uint64_t));
    int done = 0;

    for (int i = 0; i < iterations; i++)
    {
        es_client_t *client = NULL;

        struct timespec beforeCreate;
        clock_gettime(CLOCK_MONOTONIC, &beforeCreate);

        es_new_client_result_t result = es_new_descendants_client(&client, ^(es_client_t *c, const es_message_t *m) {
            (void)c;
            (void)m;
        });

        struct timespec afterCreate;
        clock_gettime(CLOCK_MONOTONIC, &afterCreate);

        if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
        {
            printf("churn stopped at %d: %d %s\n", i, result, ResultName(result));
            break;
        }

        SubscribeLightly(client);

        struct timespec beforeDelete;
        clock_gettime(CLOCK_MONOTONIC, &beforeDelete);
        es_delete_client(client);
        struct timespec afterDelete;
        clock_gettime(CLOCK_MONOTONIC, &afterDelete);

        createNanos[done] = (uint64_t)(afterCreate.tv_sec - beforeCreate.tv_sec) * 1000000000ull
            + (uint64_t)(afterCreate.tv_nsec - beforeCreate.tv_nsec);
        deleteNanos[done] = (uint64_t)(afterDelete.tv_sec - beforeDelete.tv_sec) * 1000000000ull
            + (uint64_t)(afterDelete.tv_nsec - beforeDelete.tv_nsec);
        done++;
    }

    uint64_t createTotal = 0;
    uint64_t createMax = 0;
    uint64_t deleteTotal = 0;
    uint64_t deleteMax = 0;
    for (int i = 0; i < done; i++)
    {
        createTotal += createNanos[i];
        deleteTotal += deleteNanos[i];
        if (createNanos[i] > createMax) { createMax = createNanos[i]; }
        if (deleteNanos[i] > deleteMax) { deleteMax = deleteNanos[i]; }
    }

    if (done > 0)
    {
        printf("CHURN_ITERATIONS=%d CREATE_MEAN_US=%llu CREATE_MAX_US=%llu DELETE_MEAN_US=%llu DELETE_MAX_US=%llu\n",
               done,
               (unsigned long long)(createTotal / (uint64_t)done / 1000),
               (unsigned long long)(createMax / 1000),
               (unsigned long long)(deleteTotal / (uint64_t)done / 1000),
               (unsigned long long)(deleteMax / 1000));
    }

    free(createNanos);
    free(deleteNanos);
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "perprocess";

    if (strcmp(mode, "child") == 0)
    {
        return RunChild();
    }

    if (strcmp(mode, "systemwide") == 0)
    {
        return RunSystemWide(argv[0], argc > 2 ? atoi(argv[2]) : 64);
    }

    if (strcmp(mode, "churn") == 0)
    {
        return RunChurn(argc > 2 ? atoi(argv[2]) : 200);
    }

    return RunPerProcess(argc > 2 ? atoi(argv[2]) : 64);
}
