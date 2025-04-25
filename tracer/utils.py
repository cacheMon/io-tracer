import argparse

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

def logger(error_scale,string):
    """
    A simple logger function that prints the provided string.
    """
    if error_scale == "warning":
        logo = "[WARN]"
    elif error_scale == "error":
        logo = "[ERROR]"
    elif error_scale == "info":
        logo = "[INFO]"
    else:
        logo = "[]"
    print(logo + " " + string)