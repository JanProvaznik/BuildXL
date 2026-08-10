// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Answers two questions about es_new_descendants_client that no amount of reading the headers
// settles, and that both turned out to matter:
//
//   1. Is the audit token in an ES_EVENT_TYPE_NOTIFY_FORK's `child` the same identity the child
//      reports on its own later events? If it is not, a process table keyed on that identity fails
//      to recognise every process it just created.
//
//   2. Does a descendants client receive delegation events (bootstrap lookup, XPC connect) whose
//      acting process is *not* a descendant? If it does, treating every such event as evidence that
//      the observed tree delegated work is wrong.
//
// Build and run:
//   clang -O1 -fblocks -o /tmp/es-identity es-identity.c -lEndpointSecurity -lbsm
//   codesign --force --sign - --entitlements <ent.plist> /tmp/es-identity
//   /tmp/es-identity
//
// Requires the Endpoint Security entitlement to be honoured; see es-check.sh.

#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <EndpointSecurity/EndpointSecurity.h>
#include <libproc.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#define MAX_FORKS 64
#define MAX_DELEGATIONS 256

struct fork_record
{
    int child_pid;
    int child_pidversion_at_fork;
    int first_pidversion_seen_later;
    int first_later_op_was_exec;
    int saw_later;
    int saw_exec;
    int pidversion_before_exec;
    int pidversion_on_exec;
    int pidversion_after_exec;
    int pidversion_exec_target;
};

static struct fork_record g_forks[MAX_FORKS];
static int g_fork_count = 0;

struct delegation_record
{
    int pid;
    int ppid;
    char exe[256];
    int is_descendant;
};

static struct delegation_record g_delegations[MAX_DELEGATIONS];
static int g_delegation_count = 0;

static int g_self_pid = 0;
static dispatch_queue_t g_queue = NULL;

static int IsDescendantOfSelf(pid_t pid)
{
    // Walks the live ancestry. A process that has already exited breaks the walk, in which case the
    // honest answer is "cannot tell", reported as -1 rather than guessed.
    for (int hops = 0; hops < 64; hops++)
    {
        if (pid == g_self_pid)
        {
            return 1;
        }

        if (pid <= 1)
        {
            return 0;
        }

        struct proc_bsdinfo info;
        if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, sizeof(info)) != (int)sizeof(info))
        {
            return -1;
        }

        pid = (pid_t)info.pbi_ppid;
    }

    return -1;
}

static void RecordFork(const es_message_t *message)
{
    if (g_fork_count >= MAX_FORKS)
    {
        return;
    }

    const audit_token_t child = message->event.fork.child->audit_token;
    g_forks[g_fork_count].child_pid = audit_token_to_pid(child);
    g_forks[g_fork_count].child_pidversion_at_fork = audit_token_to_pidversion(child);
    g_forks[g_fork_count].first_pidversion_seen_later = -1;
    g_forks[g_fork_count].first_later_op_was_exec = 0;
    g_forks[g_fork_count].saw_later = 0;
    g_forks[g_fork_count].saw_exec = 0;
    g_forks[g_fork_count].pidversion_before_exec = -1;
    g_forks[g_fork_count].pidversion_on_exec = -1;
    g_forks[g_fork_count].pidversion_after_exec = -1;
    g_forks[g_fork_count].pidversion_exec_target = -1;
    g_fork_count++;
}

static void RecordLater(const es_message_t *message)
{
    const int pid = audit_token_to_pid(message->process->audit_token);
    const int pidversion = audit_token_to_pidversion(message->process->audit_token);

    for (int i = 0; i < g_fork_count; i++)
    {
        if (g_forks[i].child_pid != pid)
        {
            continue;
        }

        if (!g_forks[i].saw_later)
        {
            g_forks[i].saw_later = 1;
            g_forks[i].first_pidversion_seen_later = pidversion;
            g_forks[i].first_later_op_was_exec = (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC);
        }

        // The identity a process reports can differ before and after it execs. Recording all three
        // points - at fork, on the exec message itself, and on the first message after the exec -
        // is what distinguishes "fork reports a provisional identity" from "exec renumbers the
        // process", and the two call for different fixes.
        if (message->event_type == ES_EVENT_TYPE_NOTIFY_EXEC)
        {
            if (!g_forks[i].saw_exec)
            {
                g_forks[i].saw_exec = 1;
                g_forks[i].pidversion_on_exec = pidversion;
                g_forks[i].pidversion_exec_target =
                    audit_token_to_pidversion(message->event.exec.target->audit_token);
            }
        }
        else if (g_forks[i].saw_exec && g_forks[i].pidversion_after_exec < 0)
        {
            g_forks[i].pidversion_after_exec = pidversion;
        }
        else if (!g_forks[i].saw_exec)
        {
            g_forks[i].pidversion_before_exec = pidversion;
        }

        return;
    }
}

static void RecordDelegation(const es_message_t *message)
{
    if (g_delegation_count >= MAX_DELEGATIONS)
    {
        return;
    }

    const int pid = audit_token_to_pid(message->process->audit_token);

    for (int i = 0; i < g_delegation_count; i++)
    {
        if (g_delegations[i].pid == pid)
        {
            return;
        }
    }

    struct delegation_record *record = &g_delegations[g_delegation_count++];
    record->pid = pid;
    record->ppid = (int)message->process->ppid;
    record->is_descendant = IsDescendantOfSelf((pid_t)pid);
    record->exe[0] = '\0';

    if (message->process->executable != NULL)
    {
        const es_string_token_t path = message->process->executable->path;
        size_t length = path.length < sizeof(record->exe) - 1 ? path.length : sizeof(record->exe) - 1;
        memcpy(record->exe, path.data, length);
        record->exe[length] = '\0';
    }
}

int main(void)
{
    g_self_pid = (int)getpid();
    g_queue = dispatch_queue_create("es-identity", DISPATCH_QUEUE_SERIAL);

    es_client_t *client = NULL;
    es_new_client_result_t result = es_new_descendants_client(&client, ^(es_client_t *c, const es_message_t *message) {
        (void)c;
        switch (message->event_type)
        {
            case ES_EVENT_TYPE_NOTIFY_FORK:
                RecordFork(message);
                break;
            case ES_EVENT_TYPE_NOTIFY_BOOTSTRAP_LOOK_UP:
            case ES_EVENT_TYPE_NOTIFY_XPC_CONNECT:
            case ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT:
                RecordDelegation(message);
                break;
            default:
                RecordLater(message);
                break;
        }
    });

    if (result != ES_NEW_CLIENT_RESULT_SUCCESS)
    {
        fprintf(stderr, "es_new_descendants_client failed: %d\n", (int)result);
        return 2;
    }

    es_event_type_t events[] = {
        ES_EVENT_TYPE_NOTIFY_FORK,
        ES_EVENT_TYPE_NOTIFY_EXEC,
        ES_EVENT_TYPE_NOTIFY_OPEN,
        ES_EVENT_TYPE_NOTIFY_CLOSE,
        ES_EVENT_TYPE_NOTIFY_LOOKUP,
        ES_EVENT_TYPE_NOTIFY_EXIT,
        ES_EVENT_TYPE_NOTIFY_BOOTSTRAP_LOOK_UP,
        ES_EVENT_TYPE_NOTIFY_XPC_CONNECT,
        ES_EVENT_TYPE_NOTIFY_UIPC_CONNECT,
    };

    if (es_subscribe(client, events, sizeof(events) / sizeof(events[0])) != ES_RETURN_SUCCESS)
    {
        fprintf(stderr, "es_subscribe failed\n");
        return 3;
    }

    // A child that forks but does *not* exec, so the two candidate explanations for an identity
    // change - "fork reports a provisional identity" and "exec renumbers the process" - can be told
    // apart. The grandchild only opens a file.
    pid_t child = fork();
    if (child == 0)
    {
        pid_t grandchild = fork();
        if (grandchild == 0)
        {
            FILE *f = fopen("/dev/null", "r");
            if (f != NULL)
            {
                fclose(f);
            }
            _exit(0);
        }

        int status = 0;
        waitpid(grandchild, &status, 0);

        // And one that does exec, for the comparison.
        execl("/bin/sh", "sh", "-c", "cat /dev/null", (char *)NULL);
        _exit(0);
    }

    int status = 0;
    waitpid(child, &status, 0);

    // posix_spawn separately, because that is how the broker starts a pip and the kernel implements
    // it as its own path rather than as fork followed by exec in userspace.
    pid_t spawned = 0;
    char *const spawn_argv[] = {(char *)"sh", (char *)"-c", (char *)"cat /dev/null", NULL};
    extern char **environ;
    if (posix_spawnp(&spawned, "/bin/sh", NULL, NULL, spawn_argv, environ) == 0)
    {
        int spawn_status = 0;
        waitpid(spawned, &spawn_status, 0);
        printf("SPAWNED_PID=%d\n", (int)spawned);
    }

    usleep(700000);

    es_unsubscribe_all(client);
    es_delete_client(client);

    printf("=== fork identity ===\n");
    int mismatches = 0;
    int mismatches_without_exec = 0;
    for (int i = 0; i < g_fork_count; i++)
    {
        if (!g_forks[i].saw_later)
        {
            continue;
        }

        const int changed = g_forks[i].child_pidversion_at_fork != g_forks[i].first_pidversion_seen_later;
        mismatches += changed;
        if (changed && !g_forks[i].first_later_op_was_exec)
        {
            mismatches_without_exec++;
        }

        printf("  pid=%d fork_pidversion=%d later_pidversion=%d first_later_was_exec=%d %s\n",
               g_forks[i].child_pid,
               g_forks[i].child_pidversion_at_fork,
               g_forks[i].first_pidversion_seen_later,
               g_forks[i].first_later_op_was_exec,
               changed ? "CHANGED" : "stable");

        if (g_forks[i].saw_exec)
        {
            printf("      across exec: before=%d on_exec=%d exec_target=%d after=%d %s\n",
                   g_forks[i].pidversion_before_exec,
                   g_forks[i].pidversion_on_exec,
                   g_forks[i].pidversion_exec_target,
                   g_forks[i].pidversion_after_exec,
                   (g_forks[i].pidversion_after_exec >= 0
                    && g_forks[i].pidversion_after_exec != g_forks[i].child_pidversion_at_fork)
                       ? "EXEC CHANGED IDENTITY"
                       : "exec preserved identity");
        }
    }

    printf("FORK_IDENTITY_MISMATCHES=%d NON_EXEC_MISMATCHES=%d\n", mismatches, mismatches_without_exec);

    printf("=== delegation event sources ===\n");
    int foreign = 0;
    int unknown = 0;
    for (int i = 0; i < g_delegation_count; i++)
    {
        if (g_delegations[i].is_descendant == 0)
        {
            foreign++;
        }
        else if (g_delegations[i].is_descendant < 0)
        {
            unknown++;
        }

        printf("  pid=%d ppid=%d descendant=%d exe=%s\n",
               g_delegations[i].pid,
               g_delegations[i].ppid,
               g_delegations[i].is_descendant,
               g_delegations[i].exe);
    }

    printf("DELEGATION_SOURCES=%d FOREIGN=%d UNKNOWN=%d\n", g_delegation_count, foreign, unknown);
    return 0;
}
