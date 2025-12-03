from datetime import datetime
import random

from .sampler.ProcessSampler import ProcessSampler
from ...utility.utils import format_csv_row, logger, compress_log, simple_hash
from ..WriterManager import WriteManager
import psutil
import time
import threading

class ProcessSnapper:
    def __init__(self, wm: WriteManager, anonymous: bool):
        self.wm = wm
        self.processes = []
        self.anonymous = anonymous
        
        self.sampler = ProcessSampler()
        self.sampler.start()
        self.running = True

    def stop_snapper(self):
        self.running = False
        self.sampler.stop()

    def process_snapshot(self):

        while self.running:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            for proc in psutil.process_iter(['pid', 'name', 'memory_info','cmdline','create_time','status']):
                time.sleep(random.uniform(.2, .5))
                try:
                    ts = timestamp
                    pid = proc.info['pid']
                    name = proc.info['name'] or ''
                    mem = proc.info['memory_info'].rss / 1024 
                    cmdline = ' '.join(proc.info['cmdline'])
                    if self.anonymous:
                        cmdline = simple_hash(cmdline, length=12)
                    create_time = float(proc.info['create_time'])
                    status = proc.info.get('status','')


                    cpu_5s = self.sampler.cpu_percent_for_interval(pid, create_time, 5.0) or 0.0
                    cpu_2m = self.sampler.cpu_percent_for_interval(pid, create_time, 120.0) or 0.0
                    cpu_1h = self.sampler.cpu_percent_for_interval(pid, create_time, 3600.0) or 0.0

                    out = format_csv_row(ts, pid, name, cmdline, datetime.fromtimestamp(create_time), cpu_5s, cpu_2m, cpu_1h, mem, status)
                    print(out)
                    
                    self.wm.append_process_log(out)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, Exception):
                    pass
            time.sleep(60)

    def run(self):
        snapper_thread = threading.Thread(target=self.process_snapshot)
        snapper_thread.daemon = True
        snapper_thread.start()

