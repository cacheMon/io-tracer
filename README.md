# IO-Tracer

## Installation
```
sudo apt-get install bpfcc-tools linux-headers-$(uname -r)
```

## iotrc
| Need sudo privilege
```
usage: iotrc.py [-h] [-o OUTPUT] [-b BPF_FILE] [-p PAGE_CNT] [-v VERBOSE] [-d DURATION] [-f FLUSH_THRESHOLD] [-tw TIME_WINDOW]

Trace IO syscalls

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output Directory for logging, must be new!
  -b BPF_FILE, --bpf-file BPF_FILE
                        BPF C source file path
  -p PAGE_CNT, --page-cnt PAGE_CNT
                        Number of pages for perf buffer (default 8)
  -v VERBOSE, --verbose VERBOSE
                        Print verbose output
  -d DURATION, --duration DURATION
                        Duration to run the tracer in seconds. Default is NULL (run indefinitely)
  -f FLUSH_THRESHOLD, --flush_threshold FLUSH_THRESHOLD
                        Buffered flush threshold in array length (default 5000)
  -tw TIME_WINDOW, --time-window TIME_WINDOW
                        Time window for matching PIDs (default 5_000_000 ns)
```
## iotrcparse
| Need sudo privilege
```
usage: iotrcparse.py [-h] [-o OUTPUT] [-vfs VFS_LOG] [-blk BLK_LOG] [-tw TIME_WINDOW]

Parse block and vfs logs to match PIDs

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output Directory for mapper
  -vfs VFS_LOG, --vfs-log VFS_LOG
                        vfs log path
  -blk BLK_LOG, --blk-log BLK_LOG
                        block log path
  -tw TIME_WINDOW, --time-window TIME_WINDOW
                        Time window for matching PIDs (default 5_000_000 ns)
```
## iotrcanalyze
Need to use library from requirement.txt
```
usage: iotrcanalyze.py [-h] [-o OUTPUT] log_file

Analyze trace logs

positional arguments:
  log_file              Trace log file to analyze

options:
  -h, --help            show this help message and exit
  -o OUTPUT, --output OUTPUT
                        Output directory for analysis results
```