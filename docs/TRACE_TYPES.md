# Trace Types and Collection Methods

IO Tracer uses eBPF/BPF technology to intercept kernel functions and collect various types of I/O events. The tracer is composed of multiple real-time trace types and snapshot types that provide system context.

## Real-Time Trace Types

| # | Trace Type | Description | Output |
|---|------------|-------------|--------|
| 1 | [VFS Events](traces/VFS_EVENTS.md) | File system operations at the VFS layer | `fs/fs_*.csv` |
| 2 | [Block I/O Events](traces/BLOCK_IO_EVENTS.md) | Block-level device I/O operations | `ds/ds_*.csv` |
| 3 | [Page Cache Events](traces/PAGE_CACHE_EVENTS.md) | Page cache hits, misses, writebacks, evictions | `cache/cache_*.csv` |
| 4 | [Network Events](traces/NETWORK_EVENTS.md) | Network send/receive with protocol details | `nw/nw_*.csv` |
| 4a | [Connection Lifecycle](traces/CONNECTION_LIFECYCLE_EVENTS.md) | Socket creation, bind, listen, accept, connect, shutdown | `nw_conn/nw_conn_*.csv` |
| 4b | [Epoll/Multiplexing](traces/EPOLL_EVENTS.md) | I/O multiplexing (epoll, poll, select) | `nw_epoll/nw_epoll_*.csv` |
| 4c | [Socket Configuration](traces/SOCKET_CONFIG_EVENTS.md) | Socket option changes (setsockopt/getsockopt) | `nw_sockopt/nw_sockopt_*.csv` |
| 4d | [Network Drops](traces/NETWORK_DROPS_EVENTS.md) | TCP retransmissions | `nw_drop/nw_drop_*.csv` |
| 5 | [Page Fault Events](traces/PAGE_FAULT_EVENTS.md) | File-backed page faults from mmap access | `pagefault/pagefault_*.csv` |

## Snapshot Types

| # | Snapshot Type | Description | Output |
|---|--------------|-------------|--------|
| 1 | [Filesystem Snapshot](traces/FILESYSTEM_SNAPSHOT.md) | Filesystem state (paths, sizes, timestamps) | `filesystem_snap.csv.gz` |
| 2 | [Process Snapshot](traces/PROCESS_SNAPSHOT.md) | Running process information | `process_snap.csv` |
| 3 | [System Snapshot](traces/SYSTEM_SNAPSHOT.md) | Hardware and software specifications | `device_spec.txt` |

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        IO Tracer                               │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐                                           │
│  │  eBPF Program   │  ◄── Kernel probes (kprobes/kretprobes)  │
│  │  (prober.c)     │                                           │
│  └────────┬────────┘                                           │
│           │ Perf buffer                                        │
│  ┌────────▼────────┐    ┌─────────────────────────────────┐  │
│  │  IOTracer.py     │───►│  Event Callbacks                 │  │
│  │                  │    │ - _print_event (VFS)              │  │
│  │  Trace Types:    │    │ - _print_event_block (Block)      │  │
│  │  • VFS Events    │    │ - _print_event_cache (Cache)      │  │
│  │  • Block Events  │    │ - _print_event_net (Network)      │  │
│  │  • Cache Events  │    │ - _print_event_pagefault (Fault)  │  │
│  │  • Net Events    │    └─────────────────────────────────┘  │
│  │  • Page Faults   │                                          │
│  └────────┬────────┘                                           │
│           │                                                    │
│  ┌────────▼────────┐    ┌─────────────────────────────────┐  │
│  │  Snapper Classes │    │  Snapshots                        │  │
│  │                  │    │ - FilesystemSnapper              │  │
│  │  Snapshots:      │    │ - ProcessSnapper                 │  │
│  │  • Filesystem    │    │ - SystemSnapper                  │  │
│  │  • Process       │    └─────────────────────────────────┘  │
│  │  • System        │                                          │
│  └────────┬────────┘                                           │
│           │                                                    │
│  ┌────────▼────────┐                                           │
│  │  WriterManager  │    Output:                               │
│  │                  │    • fs/*.csv (VFS events)              │  │
│  │                  │    • ds/*.csv (block events)            │  │
│  │                  │    • cache/*.csv (cache events)         │  │
│  │                  │    • nw/*.csv (network events)          │  │
│  │                  │    • pagefault/*.csv (page faults)      │  │
│  │                  │    • filesystem_snapshot/*.csv.gz       │  │
│  │                  │    • process/*.csv                      │  │
│  │                  │    • system_spec/*                      │  │
│  └──────────────────┘                                           │
└─────────────────────────────────────────────────────────────────┘
```

## Performance Considerations

- **VFS tracing** has moderate overhead as it captures every file operation
- **Block tracing** is essential for understanding physical I/O patterns
- **Cache tracing** can generate high event rates; use sampling for long traces
- **Network tracing** captures connection metadata, not payload contents
- **Snapshots** are lightweight and only captured at trace start (except periodic process snapshots)
