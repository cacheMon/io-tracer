import argparse
import time
import datetime

def attach_kprobe(event, fn_name):
    global kprobes
    try:
        k = b.attach_kprobe(event=event, fn_name=fn_name)
        kprobes.append((event, k))
        return True
    except Exception as e:
        logger("error", f"Failed to attach kprobe {event}: {e}")
        return False

def argument_parser():
    parser = argparse.ArgumentParser(description='Trace VFS syscalls')
    parser.add_argument('-o', '--output', type=str, help='Output file for logging')
    parser.add_argument('-j', '--json', type=str, help='Output file for JSON format (for analysis)')
    parser.add_argument('-l', '--limit', type=int, default=0, help='Limit number of events to capture (0 = unlimited)')
    parser.add_argument('-b', '--bpf-file', type=str, default='./bpf/vfs_prober.c', help='BPF C source file path')
    parser.add_argument('-p', '--page-cnt', type=int, default=8, help='Number of pages for perf buffer (default 8)')
    parser.add_argument('-a', '--analyze', action='store_true', help='Run analyzer on completion')
    parser.add_argument('-v', '--verbose', type=bool, default=False, help='Print verbose output')
    parser.add_argument('-d', '--duration', type=int, default=10, help='Duration to run the tracer in seconds (default 10)')

def logger(error_scale,string, timestamp=False):
    """
    A simple logger function that prints the provided string.
    """
    timestamp_seconds = time.time()
    dt_object = datetime.datetime.fromtimestamp(timestamp_seconds)
    formatted_time = dt_object.strftime("%Y-%m-%d %H:%M:%S.%f")
    if error_scale == "warning":
        logo = "[WARN]"
    elif error_scale == "error":
        logo = "[ERROR]"
    elif error_scale == "info":
        logo = "[INFO]"
    else:
        logo = f"[{error_scale}]"

    if timestamp:
        timestamp_seconds = time.time()
        dt_object = datetime.datetime.fromtimestamp(timestamp_seconds)
        formatted_time = dt_object.strftime("%Y-%m-%d %H:%M:%S.%f")
        logo += f" [{formatted_time}]" 
    print(logo + " " + string)