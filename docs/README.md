# IO Tracer Documentation

This directory contains the complete documentation for IO Tracer's trace output, covering all captured event types, data formats, and system snapshots.

## Overview

| Document | Description |
|----------|-------------|
| [Trace Types](TRACE_TYPES.md) | Summary of all trace and snapshot types with architecture overview |
| [Trace Format](TRACE_FORMAT.md) | Detailed CSV output format specification for every trace category |


## Output Directory Structure

```
result/linux_trace/<MACHINE_ID>/<YYYYMMDD_HHMMSS>/
├── fs/                    # VFS traces
├── ds/                    # Block device traces
├── cache/                 # Page cache events
├── nw/                    # Network I/O traces
├── nw_conn/               # Connection lifecycle events
├── nw_epoll/              # Epoll/multiplexing events
├── nw_sockopt/            # Socket configuration events
├── nw_drop/               # Packet drops & retransmissions
├── pagefault/             # Page fault events
├── iouring/               # io_uring async I/O events
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
└── system_spec/           # System specification file
```
