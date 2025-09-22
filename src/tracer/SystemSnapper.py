from .WriterManager import WriteManager
from ..utility.utils import logger
import subprocess
import psutil
import platform
import shutil

class SystemSnapper:
    def __init__(self, writer_manager: WriteManager):
        self.wm = writer_manager

    def get_cpu_brand(self):
        system = platform.system()
        try:
            if system == "Linux":
                with open("/proc/cpuinfo") as f:
                    for line in f:
                        if "model name" in line:
                            return line.split(":", 1)[1].strip()
            elif system == "Windows":
                out = subprocess.check_output("wmic cpu get Name", shell=True, text=True)
                lines = [l.strip() for l in out.splitlines() if l.strip() and "Name" not in l]
                return lines[0] if lines else None
            else:
                return platform.processor()
        except Exception:
            return platform.processor()


    def get_gpu_brand(self):
        try:
            out = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                text=True
            )
            return [line.strip() for line in out.splitlines() if line.strip()]
        except Exception:
            return []

    def get_storage_brands(self):
        system = platform.system()
        try:
            if system == "Linux" and shutil.which("lsblk"):
                out = subprocess.check_output("lsblk -d -o NAME,MODEL,SIZE", shell=True, text=True)
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                return lines[1:]  # skip header
            elif system == "Windows":
                out = subprocess.check_output("wmic diskdrive get Model,Size", shell=True, text=True)
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                return lines[1:]  # skip header
        except Exception:
            return []
        return []

    def capture_spec_snapshot(self):
        logger('info', "Capturing system specification snapshot...")
        mem = psutil.virtual_memory()
        gpus = self.get_gpu_brand()
        storages = self.get_storage_brands()

                # --- Collect info ---
        mem = psutil.virtual_memory()
        gpus = self.get_gpu_brand()
        storages = self.get_storage_brands()

        # --- Build a single string ---
        device_specs_str = (
    f"System: {platform.system()}\n"
    f"Release: {platform.release()}\n"
    f"Version: {platform.version()}\n"
    f"Machine: {platform.machine()}\n\n"
    f"CPU Brand: {self.get_cpu_brand()}\n"
    f"CPU Cores (logical): {psutil.cpu_count(logical=True)}\n"
    f"CPU Cores (physical): {psutil.cpu_count(logical=False)}\n"
    f"CPU Frequency: {psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'} MHz\n\n"
    f"Total Memory: {round(mem.total / (1024**3), 2)} GB\n"
    f"Available Memory: {round(mem.available / (1024**3), 2)} GB\n\n"
    f"GPUs: {', '.join(gpus) if gpus else 'None detected'}\n"
    f"Storages:\n"
    f"{chr(10).join(storages) if storages else 'Could not detect'}"
)
        self.wm.direct_write("device_spec.txt", device_specs_str)
        logger('info', "System specification snapshot captured.")
