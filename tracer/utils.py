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