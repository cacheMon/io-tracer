from datetime import datetime
from ..utility.utils import logger, compress_log, simple_hash
from .WriterManager import WriteManager
import psutil
import time
import threading

class ProcessSnapper:
    def __init__(self, wm: WriteManager, anonymous: bool):
        self.wm = wm
        self.processes = []
        self.running = True
        self.anonymous = anonymous

    def stop_snapper(self):
        self.running = False

    def process_snapshot(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        while self.running:
            # logger('info',"Starting process snapshot...")
            for proc in psutil.process_iter(['pid', 'name', 'memory_info','cmdline','create_time','status']):
                try:
                    ts = timestamp
                    pid = proc.info['pid']
                    name = proc.info['name']
                    mem = proc.info['memory_info'].rss / 1024 
                    cmdline = ' '.join(proc.info['cmdline'])
                    if self.anonymous:
                        cmdline = simple_hash(cmdline, length=12)
                    create_time = datetime.fromtimestamp(proc.info['create_time'])
                    status = proc.info['status']

                    proc = psutil.Process(pid)
                    cpu_usage = proc.cpu_percent(interval=1)
                    out = f"{ts},{pid},\"{name}\",{mem},\"{cmdline}\",{create_time},{status},{cpu_usage}"
                    self.wm.append_process_log(out)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            # logger('info',"Process snapshot completed")
            time.sleep(600)

    def run(self):
        snapper_thread = threading.Thread(target=self.process_snapshot)
        snapper_thread.daemon = True
        snapper_thread.start()


if __name__ == "__main__":
    snapper = ProcessSnapper()
    snapper.process_snapshot()