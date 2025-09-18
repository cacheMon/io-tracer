from datetime import datetime
from ..utility.utils import logger, compress_log
from .WriterManager import WriteManager
import psutil
import time

class ProcessSnapper:
    def __init__(self, wm: WriteManager):
        self.wm = wm
        self.processes = []
        self.running = True

    def stop_snapper(self):
        self.running = False

    def process_snapshot(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        while self.running:
            for proc in psutil.process_iter(['pid', 'name', 'memory_info','cmdline','create_time','status']):
                try:
                    ts = timestamp
                    pid = proc.info['pid']
                    name = proc.info['name']
                    mem = proc.info['memory_info'].rss / 1024 
                    cmdline = ' '.join(proc.info['cmdline'])
                    create_time = datetime.fromtimestamp(proc.info['create_time'])
                    status = proc.info['status']
                    
                    out = f"{ts},{pid},{name},{mem},{cmdline},{create_time},{status}"
                    self.wm.append_process_log(out)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            time.sleep(600)


if __name__ == "__main__":
    snapper = ProcessSnapper()
    snapper.process_snapshot()