import pandas as pd
import numpy as np
from datetime import datetime
from ..utility.utils import logger
import tarfile


def parse_trace_log(tar_gz_path):
    """
    Parse trace log from a tar.gz archive containing trace.log
    
    Args:
        tar_gz_path: Path to tar.gz archive containing trace.log
    """
    data = []
    error_count = 0
    
    with tarfile.open(tar_gz_path, 'r:gz') as tar:
        try:
            trace_file = tar.extractfile('trace.log')
            if trace_file is None:
                raise FileNotFoundError("trace.log not found in archive")
            
            lines = trace_file.read().decode('utf-8').splitlines()
            
        except KeyError:
            raise FileNotFoundError("trace.log not found in archive")
    
    for line_number, line in enumerate(lines, 1):
        if line_number == 1:  # Skip header line
            continue

        line = line.strip()
        if not line:  # Skip empty lines
            continue
            
        parts = line.split()

        try:
            timestamp_ns = int(parts[0])
            op = parts[1]
            pid = int(parts[2])
            comm = parts[3]
            filename = parts[4]
            inode = parts[5]
            size = int(parts[6])
            lba = parts[7]
            flags = parts[8]
            op_blk = parts[9]
            
            try:
                timestamp = np.datetime64(timestamp_ns, 'ns')
            except ValueError:
                error_count += 1
                if error_count <= 10:
                    print(f"Warning: Unable to parse timestamp in line {line_number}: {line}")
                continue
            
            data.append({
                'timestamp': timestamp,
                'op': op,
                'pid': pid,
                'comm': comm,
                'filename': filename,
                'inode': inode,
                'size': size,
                'lba': lba,
                'flags': flags,
                'op_blk': op_blk
            })
        except Exception as e:
            error_count += 1
            if error_count <= 10:
                print(f"Warning: Error parsing line {line_number}: {line} - {str(e)}")
            continue
    return pd.DataFrame(data)