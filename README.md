# IO-Tracer

## Setup

```
bash ./setup.sh
```

## Usage

The program has been wrapped into a single bash script.
Ensure you have sudo privilege.

```
Usage: sudo bash ./runner.sh [options]
Options:
  -d, --duration <seconds>   Duration to trace, including compiling (default: 30 seconds)
  -o, --output <directory>   Output directory (default: vfs_trace_analysis_timestamp)
  -v, --verbose             Log outputs
  -h, --help                 Show this help message

```

Analysis folder example is in the `result` folder.

## TODO:
- Measure the tracer overhead