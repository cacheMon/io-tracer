"""
ProcessSampler - Samples process CPU utilization over time.

This module provides the ProcessSampler class which maintains a background
history of CPU usage for all processes, allowing calculation of CPU
utilization over various time intervals (5s, 2m, 1h, etc.).

The sampler runs in a background thread and periodically records CPU times
for all running processes, building a time-series history that can be
queried to calculate CPU percentages.

Example:
    sampler = ProcessSampler()
    sampler.start()  # Start background sampling
    cpu_pct = sampler.cpu_percent_for_interval(pid=1234, create_time=1234567890.0, interval=5.0)
    sampler.stop()  # Stop sampling
"""

from datetime import datetime, timezone
import time
import threading
import psutil
from collections import deque
from typing import Tuple, Dict, Deque, List, Optional


# Default sampling configuration
SAMPLE_INTERVAL = 1.0          # Sample every 1 second
MAX_INTERVAL = 3600            # Keep up to 1 hour of history
CPU_COUNT = psutil.cpu_count(logical=True) or 1

# Type definitions
ProcKey = Tuple[int, float]     # (pid, create_time) - unique process identifier
Sample = Tuple[float, float]    # (timestamp, proc_cpu_seconds)


class ProcessSampler:
    """
    Background sampler for tracking process CPU utilization.
    
    This class maintains a rolling history of CPU time samples for all
    processes on the system. It can calculate CPU utilization over
    specified time intervals by comparing CPU time at different points.
    
    Attributes:
        sample_interval: Seconds between samples (default: 1.0)
        max_interval: Maximum history to keep in seconds (default: 3600)
        history: Dict mapping ProcKey to deque of samples
        running: Whether the sampler thread is active
        
    Example:
        sampler = ProcessSampler()
        sampler.start()
        cpu = sampler.cpu_percent_for_interval(pid, create_time, 5.0)
        sampler.stop()
    """
    
    def __init__(self, sample_interval: float = SAMPLE_INTERVAL, max_interval: float = MAX_INTERVAL):
        """
        Initialize the ProcessSampler.
        
        Args:
            sample_interval: Seconds between sampling (default: 1.0)
            max_interval: Maximum history window in seconds (default: 3600)
        """
        self.sample_interval = sample_interval
        self.max_interval = max_interval
        self.history: Dict[ProcKey, Deque[Sample]] = {}
        self.lock = threading.Lock()
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self):
        """Start the background sampling thread."""
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_sampler, daemon=True)
        self.thread.start()

    def stop(self):
        """Stop the background sampling thread."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _run_sampler(self):
        """
        Main sampling loop running in background thread.
        
        Periodically samples CPU times for all running processes and
        maintains a bounded history to prevent unbounded memory growth.
        """
        while self.running:
            t = time.time()
            for proc in psutil.process_iter(attrs=('pid', 'create_time', 'cpu_times')):
                info = proc.info
                try:
                    pid = info['pid']
                    create_time = float(info['create_time'])
                    cpu_times = info.get('cpu_times')
                    if cpu_times is None:
                        continue
                    proc_cpu = (getattr(cpu_times, 'user', 0.0) + getattr(cpu_times, 'system', 0.0))
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

                key = (pid, create_time)
                with self.lock:
                    dq = self.history.get(key)
                    if dq is None:
                        maxlen = int(self.max_interval / self.sample_interval) + 3
                        dq = deque(maxlen=maxlen)
                        self.history[key] = dq
                    dq.append((t, proc_cpu))

            # Clean up old entries
            cutoff = time.time() - self.max_interval
            with self.lock:
                remove_keys = []
                for key, dq in self.history.items():
                    while dq and dq[0][0] < cutoff:
                        dq.popleft()
                    if not dq:
                        pid = key[0]
                        try:
                            p = psutil.Process(pid)
                            if p.create_time() != key[1]:
                                remove_keys.append(key)
                        except psutil.NoSuchProcess:
                            remove_keys.append(key)
                for k in remove_keys:
                    del self.history[k]

            time.sleep(self.sample_interval)

    def _find_sample_before(self, dq: Deque[Sample], target_time: float) -> Optional[Sample]:
        """
        Find the most recent sample at or before a target time.
        
        Args:
            dq: Deque of (timestamp, cpu_seconds) samples
            target_time: Time to search for
            
        Returns:
            Sample tuple or None if no suitable sample exists
        """
        if not dq:
            return None
        for ts, cpu in reversed(dq):
            if ts <= target_time:
                return (ts, cpu)
        return dq[0]

    def cpu_percent_for_interval(self, pid: int, create_time: float, interval: float) -> Optional[float]:
        """
        Calculate CPU utilization percentage over a time interval.
        
        Computes the CPU usage as a percentage of the time interval,
        accounting for the number of CPU cores.
        
        Args:
            pid: Process ID
            create_time: Process creation time (for process identity)
            interval: Time interval in seconds to measure over
            
        Returns:
            float: CPU percentage, or None if insufficient data
            
        Example:
            >>> sampler.cpu_percent_for_interval(1234, 1234567890.0, 5.0)
            15.5  # Process used 15.5% of CPU over last 5 seconds
        """
        key = (pid, create_time)
        target_time = time.time() - interval
        with self.lock:
            dq = self.history.get(key)
            if not dq or len(dq) < 2:
                return None

            newest_ts, newest_cpu = dq[-1]
            older = self._find_sample_before(dq, target_time)
            if older is None:
                return None
            older_ts, older_cpu = older

        delta_cpu = newest_cpu - older_cpu
        delta_time = newest_ts - older_ts
        if delta_time <= 0:
            return None

        # Calculate percentage (accounting for multiple CPUs)
        percent = (delta_cpu / (delta_time)) * 100.0
        # Clamp small negative values to 0 (due to timing issues)
        if percent < 0 and percent > -1e-6:
            percent = 0.0
        return percent

    def get_all_recent_pids(self) -> List[ProcKey]:
        """
        Get list of all recently sampled processes.
        
        Returns:
            List[ProcKey]: List of (pid, create_time) tuples
        """
        with self.lock:
            return list(self.history.keys())
