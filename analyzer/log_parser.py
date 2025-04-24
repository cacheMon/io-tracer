import pandas as pd
from datetime import datetime

def parse_trace_log(log_file):
    data = []
    error_count = 0
    
    with open(log_file, 'r') as f:
        for line_number, line in enumerate(f, 1):
            line = line.strip()
            
            parts = line.split()
            
            if len(parts) < 6:
                error_count += 1
                if error_count <= 10:  # Limit the number of errors we show
                    print(f"Warning: Line {line_number} doesn't have enough basic parts: {line}")
                elif error_count == 11:
                    print("Too many parsing errors, suppressing further warnings...")
                continue

            try:
                timestamp_str = parts[0]
                op = parts[1]
                pid = int(parts[2])
                comm = parts[3]
                filename = parts[4]
                
                try:
                    inode = int(parts[5])
                except ValueError:
                    if parts[5].startswith("O_"):
                        inode = 0
                        parts.insert(5, "0") 
                    else:
                        inode = 0
                
                if op in ["READ", "WRITE"] and len(parts) >= 8:
                    try:
                        size = int(parts[6])
                    except ValueError:
                        size = 0
                    
                    try:
                        lba = int(parts[7])
                    except ValueError:
                        lba = 0
                    
                    flags = parts[8] if len(parts) > 8 else "0"
                else:
                    size = int(parts[6]) if len(parts) > 6 and parts[6].isdigit() else 0
                    lba = int(parts[7]) if len(parts) > 7 and parts[7].isdigit() else 0
                    
                    if len(parts) > 8:
                        flags = parts[8]
                    elif len(parts) > 7 and not parts[7].isdigit():
                        flags = parts[7]
                    elif len(parts) > 6 and not parts[6].isdigit():
                        flags = parts[6]
                    else:
                        flags = "0"
                
                try:
                    timestamp = datetime.strptime(timestamp_str, '%H:%M:%S.%f')
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