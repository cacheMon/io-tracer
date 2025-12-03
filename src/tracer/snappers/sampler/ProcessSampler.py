from datetime import datetime, timezone
import time
import threading
import psutil
from collections import deque
from typing import Tuple, Dict, Deque, List, Optional

SAMPLE_INTERVAL = 1.0          
MAX_INTERVAL = 3600             
CPU_COUNT = psutil.cpu_count(logical=True) or 1

ProcKey = Tuple[int, float]     # (pid, create_time)
Sample = Tuple[float, float]    # (timestamp, proc_cpu_seconds)


class ProcessSampler:
    def __init__(self, sample_interval: float = SAMPLE_INTERVAL, max_interval: float = MAX_INTERVAL):
        self.sample_interval = sample_interval
        self.max_interval = max_interval
        self.history: Dict[ProcKey, Deque[Sample]] = {}
        self.lock = threading.Lock()
        self.running = False
        self.thread: Optional[threading.Thread] = None

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._run_sampler, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=1.0)

    def _run_sampler(self):
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
        if not dq:
            return None
        for ts, cpu in reversed(dq):
            if ts <= target_time:
                return (ts, cpu)
        return dq[0]

    def cpu_percent_for_interval(self, pid: int, create_time: float, interval: float) -> Optional[float]:

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

        percent = (delta_cpu / (delta_time)) * 100.0
        if percent < 0 and percent > -1e-6:
            percent = 0.0
        return percent

    def get_all_recent_pids(self) -> List[ProcKey]:
        with self.lock:
            return list(self.history.keys())
