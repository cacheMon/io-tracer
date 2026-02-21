import sys
from bcc import BPF

bpf_file = "src/tracer/prober/prober.c"
cflags = ["-Wno-duplicate-decl-specifier", "-Wno-macro-redefined", "-mllvm", "-bpf-stack-size=4096"]
import os
tp_format = "/sys/kernel/debug/tracing/events/block/block_rq_complete/format"
if os.path.exists(tp_format):
    with open(tp_format, "r") as f:
        if "cmd_flags" in f.read():
            cflags.append("-DHAS_CMD_FLAGS")

try:
    print(cflags)
    b = BPF(src_file=bpf_file.encode(), cflags=cflags)
    print("BPF Initialized successfully!")
except Exception as e:
    print(f"Failed: {e}")
