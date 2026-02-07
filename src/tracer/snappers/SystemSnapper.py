"""
SystemSnapper - Captures system hardware and software specifications.

This module provides the SystemSnapper class which gathers information
about the system including:
- CPU (brand, cores, frequency)
- GPU (detected NVIDIA cards)
- Memory (total and available)
- Storage devices
- Operating system version
- Geographic location (country code)

Example:
    snapper = SystemSnapper(writer_manager=wm)
    snapper.capture_spec_snapshot()  # Capture and write specs
"""

from ..WriterManager import WriteManager
from ...utility.utils import logger
import subprocess
import psutil
import platform
import shutil
import requests


class SystemSnapper:
    """
    Captures system hardware and software specifications.
    
    This class gathers comprehensive information about the system
    to provide context for trace analysis. It collects data on:
    - CPU details (brand, cores, frequency)
    - GPU information (if available)
    - Memory statistics
    - Storage devices
    - OS version information
    - Geographic location
    
    Attributes:
        wm: WriteManager for outputting specification data
    """
    
    def __init__(self, writer_manager: WriteManager):
        """
        Initialize the SystemSnapper.
        
        Args:
            wm: WriteManager for outputting specification data
        """
        self.wm = writer_manager

    def get_cpu_brand(self) -> str | None:
        """
        Get the CPU brand/model name.
        
        Returns:
            str: CPU model name, or None if detection fails
        """
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


    def get_gpu_brand(self) -> list[str]:
        """
        Get installed GPU brand names.
        
        Attempts to detect NVIDIA GPUs using nvidia-smi.
        
        Returns:
            list[str]: List of GPU names, empty if none detected
        """
        try:
            out = subprocess.check_output(
                ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
                text=True
            )
            return [line.strip() for line in out.splitlines() if line.strip()]
        except Exception:
            return []

    def get_storage_brands(self) -> list[str]:
        """
        Get installed storage device information.
        
        Detects storage devices (SSDs, HDDs) using lsblk on Linux
        or wmic on Windows.
        
        Returns:
            list[str]: List of storage device strings
        """
        system = platform.system()
        try:
            if system == "Linux" and shutil.which("lsblk"):
                out = subprocess.check_output("lsblk -d -o NAME,MODEL,SIZE", shell=True, text=True)
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                return lines[1:]  # Skip header
            elif system == "Windows":
                out = subprocess.check_output("wmic diskdrive get Model,Size", shell=True, text=True)
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                return lines[1:]  # Skip header
        except Exception:
            return []
        return []

    def get_country_code(self) -> str:
        """
        Get the country code based on IP geolocation.
        
        Attempts to determine the country using external IP lookup
        services as a fallback for identifying the user's location.
        
        Returns:
            str: Two-letter country code or "Unknown"
        """
        try:
            r = requests.get("https://ipapi.co/country_code/", timeout=5)
            if r.ok:
                return r.text.strip()
        except Exception:
            pass
        try:
            r = requests.get("http://ip-api.com/json/", timeout=5)
            if r.ok:
                return r.json().get("countryCode", "Unknown")
        except Exception:
            pass
        return "Unknown"

    def capture_spec_snapshot(self):
        """
        Capture all system specifications and write to file.
        
        Collects comprehensive system information and writes it
        to device_spec.txt in the system_spec output directory.
        """
        mem = psutil.virtual_memory()
        gpus = self.get_gpu_brand()
        storages = self.get_storage_brands()

        country = self.get_country_code()

        device_specs_str = (
    f"System: {platform.system()}\n"
    f"Release: {platform.release()}\n"
    f"Version: {platform.version()}\n"
    f"Machine: {platform.machine()}\n"
    f"Country: {country}\n\n"
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
