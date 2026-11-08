
// SPDX-License-Identifier: GPL-2.0

#include <string.h>
#include <stdbool.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <sys/socket.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "bpf_sockopt_helpers.h"
#include "event.h"

char _license[] SEC("license") = "GPL";


/*
 * Per-socket metadata.
 */
struct {
    __uint(type, BPF_MAP_TYPE_SK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct svc_addr);
} service_mapping SEC(".maps");

/*
 * Userspace event channel.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");


/*
 * Intercept outgoing IPv4 TCP connections.
 *
 * Preserve the original destination and redirect the connection
 * to the local proxy listener.
 */
SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    struct svc_addr *orig;

    // This proxy currently handles TCP only.
    if (ctx->type != SOCK_STREAM ||
        ctx->protocol != IPPROTO_TCP)
        return 1;

    orig = bpf_sk_storage_get(
        &service_mapping,
        ctx->sk,
        0,
        BPF_SK_STORAGE_GET_F_CREATE
    );

    // Fail closed if we cannot preserve the original destination.
    if (!orig)
        return 0;

    orig->addr = ctx->user_ip4;
    orig->port = (__be16)ctx->user_port;
    orig->pid_tgid = bpf_get_current_pid_tgid();
    orig->_pad = 0;

    // Redirect to local proxy.
    ctx->user_ip4 = bpf_htonl(0x7f000001);
    ctx->user_port = bpf_htons(10000);

    return 1;
}


/*
 * Capture the actual local endpoint after TCP has allocated
 * its source port.
 *
 * This callback runs for the outgoing TCP socket.
 */
SEC("sockops")
int proxy_sockops(struct bpf_sock_ops *skops)
{
    struct svc_addr *orig;
    struct proxy_event *event;

    if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
        return 1;

    if (skops->family != AF_INET)
        return 1;

    if (!skops->sk)
        return 1;

    // Retrieve metadata saved by connect4.
    orig = bpf_sk_storage_get(
        &service_mapping,
        skops->sk,
        0,
        0
    );

    // Ignore connections that were not intercepted.
    if (!orig)
        return 1;

    event = bpf_ringbuf_reserve(
        &events,
        sizeof(*event),
        0
    );

    /*
     * SOCK_OPS callback return values cannot abort the connection.
     * If the ring buffer is full, this event is lost.
     */
    if (!event)
        return 1;

    event->pid_tgid = orig->pid_tgid;

    // Local endpoint of the redirected client socket.
    event->client_ip4 = skops->local_ip4;

    // SOCK_OPS local_port is host byte order.
    // Store it in network byte order for userspace.
    event->client_port = bpf_htons(
        (__u16)skops->local_port
    );

    event->_pad0 = 0;

    // Original destination saved by connect4.
    event->original_ip4 = orig->addr;
    event->original_port = orig->port;

    event->_pad1 = 0;

    bpf_ringbuf_submit(event, 0);

    return 1;
}


/*
 * Expose the original destination through getpeername().
 */
SEC("cgroup/getpeername4")
int getpeername4(struct bpf_sock_addr *ctx)
{
    struct svc_addr *orig;

    if (!get_set_sk_priority(ctx))
        return 1;

    orig = bpf_sk_storage_get(
        &service_mapping,
        ctx->sk,
        0,
        0
    );

    if (!orig)
        return 1;

    ctx->user_ip4 = orig->addr;
    ctx->user_port = orig->port;

    return 1;
}
