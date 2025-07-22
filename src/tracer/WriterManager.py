import os
import sys
import json
from datetime import datetime
from ..utility.utils import logger, create_tar_gz
import threading

class WriteManager:
    def __init__(self, output_dir: str | None, split_threshold: int = 3600 * 24):
        self.current_datetime = datetime.now()
        self.split_threshold = split_threshold

        self.output_dir = output_dir if output_dir else f"./result/vfs_trace_analysis_{self.current_datetime.strftime('%Y%m%d_%H%M%S')}"
        self.output_vfs_file = f"{self.output_dir}/vfs/log/vfs_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S')}.log"
        self.output_vfs_json_file = f"{self.output_dir}/vfs/json/vfs_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S')}.json"
        self.output_block_file = f"{self.output_dir}/block/log/block_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S')}.log"
        self.output_block_json_file = f"{self.output_dir}/block/json/block_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S')}.json"
        self.output_cache_file = f"{self.output_dir}/cache/log/cache_trace_{self.current_datetime.strftime('%Y%m%d_%H%M%S')}.log"

        if not os.path.exists(self.output_dir):
            os.makedirs(f"{self.output_dir}/vfs/log")
            os.makedirs(f"{self.output_dir}/vfs/json")
            os.makedirs(f"{self.output_dir}/block/log")
            os.makedirs(f"{self.output_dir}/block/json")
            os.makedirs(f"{self.output_dir}/cache/log")
        else:
            logger("error", f"Output directory {self.output_dir} already exists. Please change the output directory to avoid overwriting files.")
            sys.exit(1)

        self._vfs_handle = None
        self._block_handle = None
        self._cache_handle = None

        self._block_json_handle = None
        self._vfs_json_handle = None

        self.json_events = []
        self.json_block_events = []

        self.log_output = ''
        self.log_block_output = ''
        self.log_cache_output = ''

    def isEventsBigEnough(self, threshold: int = 5000):
        log_output_line = self.log_output.count('\n') + 1
        log_block_output_line = self.log_block_output.count('\n') + 1
        log_cache_output_line = self.log_cache_output.count('\n') + 1
        return log_output_line >= threshold or log_block_output_line >= threshold or log_cache_output_line >= threshold

    def isTimeToSplit(self):
        current_time = datetime.now()
        time_difference = (current_time - self.current_datetime).total_seconds()
        return time_difference >= self.split_threshold

    def write_log_header(self):
        try:
            self.write_log_block(f"timestamp pid tid comm sector nr_sectors operation cpu_id parent_info bio_size\n")
            self.write_log_vfs(f"timestamp op_name pid comm filename inode size_val flags_str\n")
            self.write_log_cache(f"timestamp pid comm index status\n")
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

    def append_cache_log(self, log_output: str):
        if isinstance(log_output, str):
            self.log_cache_output += log_output + '\n'
        else:
            logger("error", "Invalid cache log output format. Expected a string.")

    def clear_events(self):
        self.json_events.clear()
        self.json_block_events.clear()
        self.log_output = ''
        self.log_block_output = ''
        self.log_cache_output = ''

    def close_handles(self):
        if self._vfs_handle:
            self._vfs_handle.close()
            self._vfs_handle = None
        if self._block_handle:
            self._block_handle.close()
            self._block_handle = None
        if self._cache_handle:
            self._cache_handle.close()
            self._cache_handle = None
        if self._vfs_json_handle:
            self._vfs_json_handle.close()
            self._vfs_json_handle = None
        if self._block_json_handle:
            self._block_json_handle.close()
            self._block_json_handle = None

    def write_log_vfs(self, log_output: str):
        output_file = self.output_vfs_file
        if self._vfs_handle is None:
            self._vfs_handle = open(output_file, 'a', buffering=8192)
        pid = os.getpid()
        self._vfs_handle.write(log_output)

        if (self.isTimeToSplit()):
            current_time = datetime.now()
            self.output_vfs_file = f"{self.output_dir}/vfs/log/vfs_trace_{current_time.strftime('%Y%m%d_%H%M%S')}.log"
            if not self._vfs_handle is None:
                self._vfs_handle.close()
                self._vfs_handle = None

    def write_log_block(self, log_output: str):
        output_file = self.output_block_file
        if self._block_handle is None:
            self._block_handle = open(output_file, 'a', buffering=8192)
        self._block_handle.write(log_output)

        if (self.isTimeToSplit()):
            current_time = datetime.now()
            self.output_block_file = f"{self.output_dir}/block/log/block_trace_{current_time.strftime('%Y%m%d_%H%M%S')}.log"
            if not self._block_handle is None:
                self._block_handle.close()
                self._block_handle = None

    def write_log_cache(self, log_output: str):
        output_file = self.output_cache_file
        if self._cache_handle is None:
            self._cache_handle = open(output_file, 'a', buffering=8192)
        self._cache_handle.write(log_output)

        if (self.isTimeToSplit()):
            current_time = datetime.now()
            self.output_cache_file = f"{self.output_dir}/cache/log/cache_trace_{current_time.strftime('%Y%m%d_%H%M%S')}.log"
            if not self._cache_handle is None:
                self._cache_handle.close()
                self._cache_handle = None

    def write_log_vfs_json(self, log_output: any): # type: ignore
        output_file = self.output_vfs_json_file
        if self._vfs_json_handle is None:
            self._vfs_json_handle = open(output_file, 'a', buffering=8192)
        json.dump(log_output, self._vfs_json_handle, indent=2)

        if (self.isTimeToSplit()):
            current_time = datetime.now()
            self.output_vfs_json_file = f"{self.output_dir}/vfs/json/vfs_trace_{current_time.strftime('%Y%m%d_%H%M%S')}.json"
            if not self._vfs_json_handle is None:
                self._vfs_json_handle.close()
                self._vfs_json_handle = None

    def write_log_block_json(self, log_output: any): # type: ignore
        output_file = self.output_block_json_file
        if self._block_json_handle is None:
            self._block_json_handle = open(output_file, 'a', buffering=8192)
        json.dump(log_output, self._block_json_handle, indent=2)

        if (self.isTimeToSplit()):
            current_time = datetime.now()
            self.output_block_json_file = f"{self.output_dir}/block/json/block_trace_{current_time.strftime('%Y%m%d_%H%M%S')}.json"
            if not self._block_json_handle is None:
                self._block_json_handle.close()
                self._block_json_handle = None

    def write_to_disk(self):
        t1 = threading.Thread(target=self.write_log_vfs, args=(self.log_output,))
        t2 = threading.Thread(target=self.write_log_block, args=(self.log_block_output,))
        t3 = threading.Thread(target=self.write_log_vfs_json, args=(self.json_events,))
        t4 = threading.Thread(target=self.write_log_block_json, args=(self.json_block_events,))
        t5 = threading.Thread(target=self.write_log_cache, args=(self.log_cache_output,))
        t1.start()
        t2.start()
        t3.start()
        t4.start()
        t5.start()

        self.clear_events()

        t1.join()
        t2.join()
        t3.join()
        t4.join()
        t5.join()