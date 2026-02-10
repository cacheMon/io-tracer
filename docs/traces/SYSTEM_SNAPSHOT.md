# System Snapshot

**Description:** Captures hardware and software specifications for trace context.

**Collection Method:**
- Queries system information once at trace start
- Uses `psutil`, `platform`, and subprocess calls
- Attempts IP geolocation for country detection

## Data Captured

Written as a plain-text key-value file.

| # | Field | Type | Description |
|---|-------|------|-------------|
| 1 | System | `string` | Operating system name (e.g., `Linux`, `Windows`) |
| 2 | Release | `string` | Kernel/OS release version (e.g., `6.5.0-44-generic`) |
| 3 | Version | `string` | Full OS version string |
| 4 | Machine | `string` | Machine hardware architecture (e.g., `x86_64`, `aarch64`) |
| 5 | Country | `string` | Two-letter country code from IP geolocation (e.g., `US`, `DE`); `Unknown` if detection fails |
| 6 | CPU Brand | `string` | CPU model name (from `/proc/cpuinfo` on Linux) |
| 7 | CPU Cores (logical) | `integer` | Number of logical CPU cores (including hyperthreads) |
| 8 | CPU Cores (physical) | `integer` | Number of physical CPU cores |
| 9 | CPU Frequency | `float` | Current CPU frequency in MHz; `N/A` if unavailable |
| 10 | Total Memory | `float` | Total system RAM in GB |
| 11 | Available Memory | `float` | Currently available RAM in GB |
| 12 | GPUs | `string` | Comma-separated list of GPU names (NVIDIA only); `None detected` if unavailable |
| 13 | Storages | `string` | List of storage devices with name, model, and size (one per line); `Could not detect` if unavailable |

**Output File:** `system_spec/device_spec.txt`
