# IO-Tracer

## How it works
Visit [IO Tracer documentations](https://raflyhangga.github.io/iotracerdocs/) for more detail.

## Installation
```
# Install are analyzing tools
pip install -r requirement.txt
```

then, install BPF Compiler Collection: [BCC Installation Link](https://github.com/iovisor/bcc/blob/master/INSTALL.md)  

## iotrc
| Need sudo privilege
```
usage: iotrc.py [-h] [-o OUTPUT] [-b BPF_FILE] [-p PAGE_CNT] [-v VERBOSE] [-d DURATION] [-s SPLIT_THRESHOLD] [-a]

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
  -s SPLIT_THRESHOLD, --split_threshold SPLIT_THRESHOLD
                        Split threshold in seconds (default 1 day)
  -a, --anonimize       Enable anonymization of process and file names
```