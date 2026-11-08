# Experiment phase journal
- let's start with cgroup and ebpf at first
- future cli:

target:  --pid 1234 | --cgroup <path> | --netns <path> | --container <name>
            │
            └─ container resolver (Docker/Podman API) → { pid, cgroup, netns }
                                                              │
backend:  LD_PRELOAD | eBPF cgroup/connect | nftables (TPROXY/REDIRECT) | TUN

proxyjail attach --container my-app --chain work
proxyjail attach --netns /run/netns/vpn1 --chain tor
proxyjail run --chain work -- curl https://example.com   # plain process, as before
proxyjail daemon --watch-label yourtool.profile          # auto-capture labeled containers
