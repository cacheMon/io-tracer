import mimetypes
import os
import threading
import time
from datetime import datetime
from pathlib import Path
from queue import Queue, Empty
import requests

from src.utility.utils import capture_machine_id, logger,get_current_tag


class ObjectStorageManager:
    def __init__(self, version: str = "vdev"):
        self._stop = threading.Event()
        self._t: list[threading.Thread] = []
        self.backend_url = "https://io-tracer-worker.1a1a11a.workers.dev"
        # self.app_version = get_current_tag()
        self.machine_id = capture_machine_id()
        self.current_datetime = datetime.now()
        self.file_queue: Queue[str] = Queue()
        self.successful_upload = 0
        self.app_version = version


    def test_connection(self) -> bool:
        try:
            logger("TEST CONNECTION", "testing....")
            r = requests.get(f"{self.backend_url}/connection-test.txt", timeout=5)
            if r.ok:
                logger("TEST CONNECTION", "Connection to remote object storage established.")
                return r.ok
            else:
                raise Exception("can't connect")
        except Exception:
            logger("warn", "Unable to reach remote object storage server.")
            logger("info", "saving traces locally")
            return False

    def get_presigned_url(self, filename: str) -> str:
        r = requests.post(
            f"{self.backend_url}/linuxtrace/"
            f"{self.app_version}/"
            f"{self.machine_id.upper()}/"
            f"{self.current_datetime.strftime('%Y%m%d_%H%M%S_%f')[:-3]}/"
            f"{filename}",
            timeout=10,
        )
        if not r.ok:
            raise RuntimeError(f"Failed to get presign: {r.status_code} {r.text}")
        return r.text

    def put_object(self, file_path: str):
        path = Path(file_path)
        if not path.is_file():
            raise FileNotFoundError(f"Not a file: {path}")

        presigned_url = self.get_presigned_url(path.name)
        content_type = mimetypes.guess_type(path.name)[0] or "application/octet-stream"

        with path.open("rb") as f:
            r = requests.put(
                presigned_url,
                data=f,
                headers={"Content-Type": content_type},
                timeout=10,
            )
        if r.ok:
            os.remove(file_path)
            self.successful_upload += 1
            logger("info", f"Files Uploaded: {self.successful_upload}", True)
        else:
            raise RuntimeError(f"Upload failed: {r.status_code} {r.text}")

    def append_object(self, file_path: str):
        self.file_queue.put(file_path)

    def _automatic_upload_worker(self):
        backoff = 1
        while True:
            if self._stop.is_set():
                break

            try:
                fp = self.file_queue.get(timeout=0.5)
            except Empty:
                continue

            try:
                self.put_object(fp)
                backoff = 1  # reset backoff after success
            except Exception as e:
                logger("warn",f"Upload error. Requeueing.")
                self.file_queue.put(fp)
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 10)
            finally:
                self.file_queue.task_done()

    def start_worker(self, daemon: bool = False, num_workers: int = 1):
        if self._t and any(t.is_alive() for t in self._t):
            return
        logger("info", f"Starting {num_workers} uploader workers")
        self._stop.clear()
        self._t = [
            threading.Thread(target=self._automatic_upload_worker, daemon=daemon)
            for _ in range(num_workers)
        ]
        for t in self._t:
            t.start()

    def clean_queue(self, timeout: float | None = None) -> bool:
        start = time.time()
        while True:
            if self.file_queue.unfinished_tasks == 0:
                return True

            if timeout is not None and (time.time() - start) >= timeout:
                return False

            time.sleep(0.1)


    def stop_worker(self, server_mode: bool, timeout: float | None = 10):
        logger("info", "Flushing pending uploads")

        if server_mode:
            drained = self.clean_queue(timeout=timeout)
            if not drained:
                logger("warn", "Timeout while waiting for uploads to finish. Some files may remain in the queue.")

        self._stop.set()

        for t in self._t:
            if t:
                t.join(timeout=timeout)
        self._t = []




