import time
from ..utility.utils import logger
import threading

class PollingThread:
    def __init__(self, bpf_instance, polling_active):
        self.bpf = bpf_instance
        self.polling_active = polling_active

    def run(self):
        while self.polling_active:
            try:
                self.bpf.perf_buffer_poll(timeout=50)
            except Exception as e:
                logger("error", f"Error in polling thread: {e}")
                time.sleep(0.01)

    def create_thread(self):
        poller = threading.Thread(target=self.run)
        poller.daemon = True
        poller.start()
        return poller