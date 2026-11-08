#ifndef PROXY_EBPF_EVENT_H
#define PROXY_EBPF_EVENT_H

#include <linux/types.h>

/*
 * Original destination metadata stored against the client socket.
 *
 * This storage is created in connect4 and retrieved later
 * from the sockops callback.
 */
struct svc_addr {
    __be32 addr;
    __be16 port;
    __u16 _pad;
    __u64 pid_tgid;
};

/*
 * Ring-buffer event.
 *
 * IMPORTANT: Keep this layout synchronized with the Rust parser.
 *
 * Total size: 24 bytes.
 *
 * Offset:
 *   0  -  8: pid_tgid
 *   8  - 12: client_ip4
 *  12  - 14: client_port
 *  14  - 16: padding
 *  16  - 20: original_ip4
 *  20  - 22: original_port
 *  22  - 24: padding
 */
struct proxy_event {
    __u64 pid_tgid;

    __be32 client_ip4;
    __be16 client_port;
    __u16 _pad0;

    __be32 original_ip4;
    __be16 original_port;
    __u16 _pad1;
};

#endif /* PROXY_EBPF_EVENT_H */
