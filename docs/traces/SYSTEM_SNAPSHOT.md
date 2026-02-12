# System Snapshot

**Description:** Captures hardware and software specifications for trace context.

**Collection Method:**
- Queries system information once at trace start
- Uses `psutil`, `platform`, and subprocess calls
- Attempts IP geolocation for country detection

## Data Captured

Written as a plain-text key-value file with fields grouped into sections separated by blank lines.

### System Information

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | System | `string` | Operating system name (e.g., `Linux`, `Windows`) |
| 2 | Release | `string` | Kernel/OS release version (e.g., `6.5.0-44-generic`) |
| 3 | Version | `string` | Full OS version string |
| 4 | Machine | `string` | Machine hardware architecture (e.g., `x86_64`, `aarch64`) |
| 5 | Country | `string` | Two-letter country code from IP geolocation (e.g., `US`, `DE`); `Unknown` if detection fails |

### CPU Information

| # | Field | Type | Description |
|---|-------|------|-------------|
| 6 | CPU Brand | `string` | CPU model name (from `/proc/cpuinfo` on Linux, `wmic` on Windows) |
| 7 | CPU Cores (logical) | `integer` | Number of logical CPU cores (including hyperthreads) |
| 8 | CPU Cores (physical) | `integer` | Number of physical CPU cores |
| 9 | CPU Frequency | `string` | Current CPU frequency with unit (e.g., `1800.0 MHz`); `N/A MHz` if unavailable |

### Memory Information

| # | Field | Type | Description |
|---|-------|------|-------------|
| 10 | Total Memory | `string` | Total system RAM with unit (e.g., `15.89 GB`) |
| 11 | Available Memory | `string` | Currently available RAM with unit (e.g., `8.45 GB`) |

### Hardware Devices

| # | Field | Type | Description |
|---|-------|------|-------------|
| 12 | GPUs | `string` | Comma-separated list of GPU names (NVIDIA only via `nvidia-smi`); `None detected` if unavailable |
| 13 | Storages | `string` | List of storage devices with name, model, and size (one per line via `lsblk` on Linux, `wmic` on Windows); `Could not detect` if unavailable |

## Output Format Example

```
System: Linux
Release: 6.5.0-44-generic
Version: #44-Ubuntu SMP PREEMPT_DYNAMIC ...
Machine: x86_64
Country: US

CPU Brand: Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz
CPU Cores (logical): 16
CPU Cores (physical): 8
CPU Frequency: 2900.0 MHz

Total Memory: 15.89 GB
Available Memory: 8.45 GB

GPUs: NVIDIA GeForce RTX 3080
Storages:
nvme0n1  Samsung SSD 980 PRO 1TB  1000.2G
sda      WDC WD10EZEX-00W         1000.2G
```

**Output File:** `system_spec/device_spec.txt`
