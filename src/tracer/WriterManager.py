import os
import sys
import json
from datetime import datetime
from ..utility.utils import logger
import threading

class WriteManager:
    def __init__(self, output_dir: str | None):
        self.output_dir = output_dir if output_dir else f"./result/vfs_trace_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self.output_vfs_file = f"{self.output_dir}/vfs_trace.log"
        self.output_vfs_json_file = f"{self.output_dir}/vfs_trace.json"
        self.output_block_file = f"{self.output_dir}/block_trace.log"
        self.output_block_json_file = f"{self.output_dir}/block_trace.json"

        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
        else:
            logger("error", f"Output directory {self.output_dir} already exists. Please change the output directory to avoid overwriting files.")
            sys.exit(1)

        self._vfs_handle = None
        self._block_handle = None
        self._vfs_json_handle = None
        self._block_json_handle = None

        self.json_events = []
        self.json_block_events = []
        self.log_output = ''
        self.log_block_output = ''

    def isEventsBigEnough(self, threshold: int = 5000):
        return len(self.json_events) >= threshold or len(self.json_block_events) >= threshold


    def write_log_header(self):
        try:
            self.write_log_block(f"timestamp pid comm sector nr_sectors operation\n")
            self.write_log_vfs(f"timestamp op_name pid comm filename inode size_val flags_str\n")
            # if self.verbose:
            #     logger("info", f"Logging to {self.output}")
        except IOError as e:
            logger("info", f"could not open output file': {e}")
            sys.exit(1)

    def append_fs_json(self, json_event: dict):
        if isinstance(json_event, dict):
            self.json_events.append(json_event)
        else:
            logger("error", "Invalid JSON event format. Expected a dictionary.")

    def append_block_json(self, json_event: dict):
        if isinstance(json_event, dict):
            self.json_block_events.append(json_event)
        else:
            logger("error", "Invalid JSON event format. Expected a dictionary.")

    def append_fs_log(self, log_output: str):
        if isinstance(log_output, str):
            self.log_output += log_output + '\n'
        else:
            logger("error", "Invalid log output format. Expected a string.")

    def append_block_log(self, log_output: str):
        if isinstance(log_output, str):
            self.log_block_output += log_output + '\n'
        else:
            logger("error", "Invalid block log output format. Expected a string.")

    def clear_events(self):
        self.json_events.clear()
        self.json_block_events.clear()
        self.log_output = ''
        self.log_block_output = ''

    def close_handles(self):
        if self._vfs_handle:
            self._vfs_handle.close()
            self._vfs_handle = None
        if self._block_handle:
            self._block_handle.close()
            self._block_handle = None
        if self._vfs_json_handle:
            self._vfs_json_handle.close()
            self._vfs_json_handle = None
        if self._block_json_handle:
            self._block_json_handle.close()
            self._block_json_handle = None

    def write_log_vfs(self, log_output: str):
        if self._vfs_handle is None:
            self._vfs_handle = open(self.output_vfs_file, 'a', buffering=8192)
        self._vfs_handle.write(log_output)

    def write_log_vfs_json(self, log_output: any): # type: ignore
        if self._vfs_json_handle is None:
            self._vfs_json_handle = open(self.output_vfs_json_file, 'a', buffering=8192)
        json.dump(log_output, self._vfs_json_handle, indent=2)
    def write_log_block(self, log_output: str):
        if self._block_handle is None:
            self._block_handle = open(self.output_block_file, 'a', buffering=8192)
        self._block_handle.write(log_output)

    def write_log_block_json(self, log_output: any): # type: ignore
        if self._block_json_handle is None:
            self._block_json_handle = open(self.output_block_json_file, 'a', buffering=8192)
        json.dump(log_output, self._block_json_handle, indent=2)

    def write_to_disk(self):
        t1 = threading.Thread(target=self.write_log_vfs, args=(self.log_output,))
        t2 = threading.Thread(target=self.write_log_block, args=(self.log_block_output,))
        t3 = threading.Thread(target=self.write_log_vfs_json, args=(self.json_events,))
        t4 = threading.Thread(target=self.write_log_block_json, args=(self.json_block_events,))
        t1.start()
        t2.start()
        t3.start()
        t4.start()

        self.clear_events()

        t1.join()
        t2.join()
        t3.join()
        t4.join()