#!/usr/bin/env python3

import argparse

from src.tracer.IOTracer import IOTracer
from pathlib import Path
import sys

def install_autostart():
    autostart_dir = Path.home() / '.config' / 'autostart'
    desktop_file = autostart_dir / 'iotracer.desktop'
    
    autostart_dir.mkdir(parents=True, exist_ok=True)
    
    script_path = Path(__file__).resolve()
    default_output = Path.home() / 'IOTracer' / 'traces'
    
    desktop_content = f"""[Desktop Entry]
Type=Application
Name=IO Tracer
Comment=System I/O monitoring tool
Exec=pkexec python3 {script_path} --output {default_output}
Terminal=false
Hidden=false
X-GNOME-Autostart-enabled=true
Categories=System;Monitor;
"""
    
    desktop_file.write_text(desktop_content)
    print(f"autostart enabled at: \t\t{desktop_file}")
    print(f"default output: \t\t{default_output}")
    print(f"NOTE: You will be prompted for password on each boot")
    print(f"to disable: python3 {script_path} --disable-autostart\n")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Trace IO syscalls')
    parser.add_argument('-o', '--output', type=str, default="./result", help='Output Directory for logging, must be new!')
    parser.add_argument('-v', '--verbose', type=bool, default=False, help='Print verbose output')
    parser.add_argument('-a', '--anonimize', action='store_true', help='Enable anonymization of process and file names')
    parser.add_argument('-au', '--auto-upload', action='store_true', help='Enable anonymization of process and file names')
    parser.add_argument('--enable-autostart', action='store_true', help='Enable autostart on system boot')
    parser.add_argument('--disable-autostart', action='store_true', help='Disable autostart on system boot')

    parse_args = parser.parse_args()
    if parse_args.enable_autostart:
        print("="*20)
        install_autostart()
        sys.exit(0)

    if parse_args.disable_autostart:
        desktop_file = Path.home() / '.config' / 'autostart' / 'iotracer.desktop'
        print("="*20)
        if desktop_file.exists():
            desktop_file.unlink()
            print("Autostart disabled")
        else:
            print("Autostart was not enabled")
        sys.exit(0)
    output_dir = parse_args.output.strip()

    tracer = IOTracer(
        output_dir=output_dir,
        bpf_file='./src/tracer/prober/prober.c',
        page_cnt=8,
        verbose=parse_args.verbose,
        anonymous=parse_args.anonimize,
        automatic_upload=parse_args.auto_upload,
    )
    tracer.trace()
