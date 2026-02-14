# Multi-Part Filesystem Snapshot Implementation

## Overview

The filesystem snapshot feature now supports splitting large filesystem scans into multiple compressed parts to optimize memory usage.

## How It Works

### File Naming Convention

Each part of a filesystem snapshot follows this naming pattern:

```
filesystem_snapshot_part####_TIMESTAMP_DEVICEID.csv.gz
```

Where:
- `part####`: Zero-padded part number (e.g., `part0001`, `part0002`, ...)
- `TIMESTAMP`: Snapshot start time in `YYYYMMDD_HHMMSS` format
- `DEVICEID`: Uppercase machine identifier

### Completion Marker

The final part is renamed to indicate completion:

```
filesystem_snapshot_part####_TIMESTAMP_DEVICEID_complete_partsN.csv.gz
```

The `_complete_partsN` suffix indicates:
- This is the last part of the snapshot
- `N` is the total number of parts in this snapshot

### Example

A 3-part filesystem snapshot might produce these files:

```
filesystem_snapshot_part0001_20260214_120000_ABC123DEF456.csv.gz
filesystem_snapshot_part0002_20260214_120000_ABC123DEF456.csv.gz
filesystem_snapshot_part0003_20260214_120000_ABC123DEF456_complete_parts3.csv.gz
```

## Compression

Files are compressed using **gzip** for reliable and efficient compression.

## Implementation Details

### WriterManager Changes

1. **New Instance Variables**:
   - `fs_snapshot_part_number`: Tracks current part number
   - `fs_snapshot_timestamp`: Snapshot session timestamp
   - `fs_snapshot_device_id`: Machine/device identifier
   - `fs_snapshot_session_active`: Whether a snapshot session is active

2. **New Methods**:
   - `start_fs_snapshot_session()`: Initialize a new snapshot session
   - `mark_fs_snapshot_complete()`: Rename final part with completion marker

3. **Modified Methods**:
   - `flush_fssnap_only()`: Now writes to part-based files with gzip compression

### FilesystemSnapper Changes

The `filesystem_snapshot()` method now calls `mark_fs_snapshot_complete()` after completing the scan to mark the final part.

### Utils Changes

Uses the existing `compress_log()` function that:
- Compresses files using gzip
- Removes the original uncompressed file after compression

## Buffer Flushing

The filesystem snapshot buffer is flushed when it reaches the threshold (`fs_snap_max_events`, default 8000 entries). Each flush creates a new part file. This prevents memory overflow during large filesystem scans.

## Memory Optimization

By splitting snapshots into parts:
- Memory usage is bounded by the buffer size
- Each part is compressed immediately after writing
- Original uncompressed files are removed after compression
- Large filesystem scans can complete without memory issues

## Reading Multi-Part Snapshots

To reconstruct a complete snapshot:

1. Locate all parts with matching `TIMESTAMP` and `DEVICEID`
2. Sort parts by part number
3. Verify the last part has the `_complete_partsN` suffix
4. Decompress and concatenate all parts in order

The total number of parts is indicated by the `N` value in the completion marker.

## Dependencies

This feature requires:
- All parts must have consistent timestamp and device ID
- gzip is available by default in Python's standard library
