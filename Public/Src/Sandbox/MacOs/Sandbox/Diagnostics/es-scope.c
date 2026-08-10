#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static _Atomic unsigned long long g_total = 0, g_gaps = 0, g_prev = 0, g_marker = 0, g_platform = 0;
static _Atomic unsigned long long g_foreign = 0;
static char *g_seen;
static _Atomic int g_nseen = 0;
static const char *MARK = "bxlscope-foreign-canary";

int main(void)
{
    g_seen = calloc(256, 256);
    es_client_t *c = NULL;
    es_new_client_result_t r = es_new_descendants_client(&c, ^(es_client_t *cl, const es_message_t *m) {
        (void)cl;
        g_total++;
        unsigned long long gs = m->global_seq_num;
        if (g_total > 1 && gs > g_prev + 1) g_gaps += gs - g_prev - 1;
        g_prev = gs;
        if (m->process->is_platform_binary) g_platform++;
        const char *p = m->process->executable->path.data;
        size_t plen = m->process->executable->path.length;
        if (strstr(p, MARK)) g_foreign++;
        int n = g_nseen, found = 0;
        for (int i = 0; i < n; i++) {
            if (!strncmp(g_seen + i * 256, p, 255)) { found = 1; break; }
        }
        if (!found && n < 256) {
            size_t cp = plen < 255 ? plen : 255;
            memcpy(g_seen + n * 256, p, cp);
            g_seen[n * 256 + cp] = 0;
            g_nseen = n + 1;
        }
        if (m->event_type == ES_EVENT_TYPE_NOTIFY_OPEN && m->event.open.file &&
            strstr(m->event.open.file->path.data, MARK)) g_marker++;
    });
    if (r != ES_NEW_CLIENT_RESULT_SUCCESS) { printf("client failed=%d\n", r); return 1; }

    es_event_type_t evs[] = {ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
                             ES_EVENT_TYPE_NOTIFY_OPEN, ES_EVENT_TYPE_NOTIFY_CLOSE, ES_EVENT_TYPE_NOTIFY_STAT,
                             ES_EVENT_TYPE_NOTIFY_LOOKUP};
    es_subscribe(c, evs, sizeof(evs) / sizeof(evs[0]));
    system("/bin/sh -c '/bin/ls /usr/bin >/dev/null; /usr/bin/grep -q root /etc/passwd'");
    sleep(3);
    es_unsubscribe_all(c);
    printf("TOTAL=%llu GAPS=%llu FOREIGN_PROC=%llu FOREIGN_PATH=%llu PLATFORM_BINARY_EVENTS=%llu DISTINCT_EXE=%d\n",
           (unsigned long long)g_total, (unsigned long long)g_gaps, (unsigned long long)g_foreign,
           (unsigned long long)g_marker, (unsigned long long)g_platform, (int)g_nseen);
    for (int i = 0; i < g_nseen; i++) printf("  EXE %s\n", g_seen + i * 256);
    es_delete_client(c);
    return 0;
}
