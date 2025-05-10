import pandas as pd
import numpy as np
from datetime import datetime

def parse_trace_log(log_file):
    data = []
    error_count = 0
    
    with open(log_file, 'r') as f:
        for line_number, line in enumerate(f, ):
            if line_number == 0:
                continue

            line = line.strip()
            parts = line.split()

            try:
                timestamp_ns = int(parts[0])
                op = parts[1]
                pid = int(parts[2])
                comm = parts[3]
                filename = parts[4]
                inode = int(parts[5])
                size = int(parts[6])
                lba = int(parts[7])
                flags = parts[8]
                
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
                    'flags': flags
                })
            except Exception as e:
                error_count += 1
                if error_count <= 10:
                    print(f"Warning: Error parsing line {line_number}: {line} - {str(e)}")
                continue
    
    if not data:
        print("Warning: No valid data could be parsed from the log file")
    else:
        print(f"Successfully parsed {len(data)} log entries with {error_count} errors")
        
    return pd.DataFrame(data)