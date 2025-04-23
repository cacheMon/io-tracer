import pandas as pd
from datetime import datetime

def parse_trace_log(log_file):
    data = []
    
    with open(log_file, 'r') as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            
            parts = line.split()
            
            if len(parts) < 5:
                print(f"Warning: Line {line_number} doesn't have enough parts: {line}")
                continue

            try:
                timestamp_str = parts[0]
                op = parts[1]
                pid = int(parts[2])
                comm = parts[3]
                
                if op == "OPEN" and len(parts) >= 6:
                    filename = parts[4]
                    inode = int(parts[5])
                    size = 0
                    lba = 0
                    flags = parts[6] if len(parts) > 6 else "0"
                elif op in ["READ", "WRITE"] and len(parts) >= 9:
                    filename = parts[4]
                    inode = int(parts[5])
                    size = int(parts[6])
                    lba = int(parts[7])
                    flags = parts[8]
                elif len(parts) >= 7:
                    filename = parts[4]
                    inode = int(parts[5])
                    flags = parts[6]
                    size = 0
                    lba = 0
                else:
                    filename = parts[4] if len(parts) > 4 else ""
                    inode = int(parts[5]) if len(parts) > 5 and parts[5].isdigit() else 0
                    size = 0
                    lba = 0
                    flags = parts[-1] 
                try:
                    timestamp = datetime.strptime(timestamp_str, '%H:%M:%S.%f')
                except ValueError:
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
                print(f"Warning: Error parsing line {line_number}: {line} - {str(e)}")
                continue
    
    if not data:
        print("Warning: No valid data could be parsed from the log file")
    else:
        print(f"Successfully parsed {len(data)} log entries")
        
    return pd.DataFrame(data)