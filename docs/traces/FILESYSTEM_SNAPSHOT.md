# Filesystem Snapshot

**Description:** Records the state of the filesystem at trace start and periodically during the trace, capturing file paths, sizes, and timestamps.

**Collection Method:**
- First snapshot runs at trace start
- Subsequent snapshots are captured every hour (3600 seconds)
- Walks the filesystem hierarchy starting from `/`
- Records files up to configurable depth (default: 3)
- Skips files on different filesystems/devices
- Tracks visited inodes to avoid duplicates (hard links)
- Can operate in anonymous mode (hashes file paths)

## Data Captured

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | Snapshot Timestamp | `datetime` | Time when this snapshot was taken (`YYYY-MM-DD HH:MM:SS`) |
| 2 | File Path | `string` | Full file path (or hashed path in anonymous mode) |
| 3 | Size | `integer` | File size in bytes |
| 4 | Creation Time | `datetime` | File creation time (`st_birthtime`); falls back to `st_mtime` if unavailable |
| 5 | Modification Time | `datetime` | Last data modification time (`st_mtime`) |
| 6 | Access Time | `datetime` | Last access time (`st_atime`) |

## Excluded Filesystems

Files on virtual/pseudo filesystems are automatically excluded by skipping different device IDs. The following filesystem types are not traversed:

| Filesystem | Description |
|------------|-------------|
| `procfs` | `/proc` — process information |
| `sysfs` | `/sys` — kernel/device configuration |
| `tmpfs` | In-memory temporary filesystem |
| `devtmpfs` | `/dev` — device nodes |
| `devpts` | Pseudo-terminal devices |
| `debugfs` | `/sys/kernel/debug` — debug filesystem |

## Anonymous Mode

When `--anonymous` is enabled, file paths are hashed using a deterministic hash function (12-character hash). Directory structure is preserved but individual path components are replaced with hashes. File extensions are kept for analysis purposes.

**Output File:** `filesystem_snapshot/filesystem_snapshot_*.csv`
