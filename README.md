# IO-Tracer

## Setup

```
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
```

## Usage

The program has been wrapped into a single bash script.
Ensure you have sudo privilege.

```
Usage: sudo bash ./runner.sh [options]
Options:
  -d, --duration <seconds>   Duration to trace (default: 30 seconds)
  -o, --output <directory>   Output directory (default: vfs_trace_analysis_timestamp)
  -w, --workload <command>   Run a specific workload while tracing
  -h, --help                 Show this help message

```

Analysis folder example is in the `result` folder.

## TODO:
- Precompile the BPF program so that i won't compile on script run
- Implement limit
