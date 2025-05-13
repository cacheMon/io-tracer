from .utils import logger
import json

class BlockToFS:
    def __init__(self, block_log:str, vfs_log:str, output_dir:str, time_window:int=50_000_000, verbose:bool=False):
        self.verbose = verbose
        self.block_log = block_log
        self.vfs_log = vfs_log
        self.output_file = output_dir+"/trace.log"
        self.output_json_file = output_dir+"/trace.json"
        self.data_block = []
        self.data_vfs = []
        self.time_window = time_window
        self.json_output = []

    def _parse_block_log(self):
        with open(self.block_log, "r") as f:
            for line_number, line in enumerate(f, ):
                if line_number == 0:
                    continue
                line = line.strip()
                parts = line.split()
                self.data_block.append({
                    'timestamp': parts[0],
                    'pid': parts[1],
                    'comm': parts[2],
                    'sector': parts[3], 
                    'nr_sectors': parts[4],
                    'operation': parts[5],
                })

    def _parse_vfs_log(self):
        with open(self.vfs_log, "r") as f:
            for line_number, line in enumerate(f, ):
                if line_number == 0:
                    continue
                line = line.strip()
                parts = line.split()

                self.data_vfs.append({
                    'timestamp': parts[0], 
                    'op_name': parts[1], 
                    'pid': parts[2], 
                    'comm': parts[3], 
                    'filename': parts[4], 
                    'inode': parts[5], 
                    'size_val': parts[6], 
                    'flags_str': parts[7],
                })

    def _find_matching_pid(self):
        """
        Perform a union operation between block and VFS data.
        Includes all records from both data sources.
        """
        
        self._find_optimal_time_window()
        output = "timestamp vfs_op_name pid comm filename inode size_val sector flags_str blk_operation\n"
        logger("info","Performing union between block and vfs data...")
        
        processed_blocks = set()
        
        # Group VFS operations by PID
        vfs_by_pid = {}
        for dvfs in self.data_vfs:
            pid = dvfs['pid']
            if pid not in vfs_by_pid:
                vfs_by_pid[pid] = []
            vfs_by_pid[pid].append(dvfs)
        
        # Process each block operation for matches
        for i, dblock in enumerate(self.data_block):
            block_pid = dblock['pid']
            block_timestamp = float(dblock['timestamp'])
            
            if block_pid in vfs_by_pid:
                closest_vfs = None
                min_time_diff = float('inf')
                
                for dvfs in vfs_by_pid[block_pid]:
                    vfs_timestamp = float(dvfs['timestamp'])
                    
                    time_diff = abs(block_timestamp - vfs_timestamp)
                    
                    if time_diff <= self._adaptive_time_window(dvfs):
                        if time_diff < min_time_diff:
                            min_time_diff = time_diff
                            closest_vfs = dvfs
                
                if closest_vfs:
                    dvfs = closest_vfs
                    timestamp = int((block_timestamp + float(dvfs['timestamp'])) // 2)
                    
                    n_vfs_opname = dvfs['op_name']
                    n_vfs_pid = dvfs['pid']
                    n_blk_comm = dblock['comm']
                    n_size = dvfs['size_val']
                    n_flags = dvfs['flags_str']
                    n_filename = dvfs['filename']
                    n_inode = dvfs['inode'] 
                    n_sector = dblock['sector']
                    n_blk_operation = dblock['operation']
                    
                    json_data = {
                        'timestamp': timestamp,
                        'op_name': n_vfs_opname,
                        'pid': n_vfs_pid,
                        'comm': n_blk_comm,
                        'filename': n_filename,
                        'inode': n_inode,
                        'size_val': n_size,
                        'sector': n_sector,
                        'flags_str': n_flags,
                        'blk_operation': n_blk_operation
                    }

                    self.json_output.append(json_data)
                    output += f"{timestamp} {n_vfs_opname} {n_vfs_pid} {n_blk_comm} {n_filename} {n_inode} {n_size} {n_sector} {n_flags} {n_blk_operation}\n"
                    
                    # Mark this block as processed
                    processed_blocks.add(i)
        
        # Now add remaining unmatched block operations
        for i, dblock in enumerate(self.data_block):
            if i not in processed_blocks:
                timestamp = float(dblock['timestamp'])
                
                json_data = {
                    'timestamp': int(timestamp),
                    'op_name': "[none]",  # No matching VFS operation
                    'pid': dblock['pid'],
                    'comm': dblock['comm'],
                    'filename': "UNKNOWN",
                    'inode': "0",
                    'size_val': dblock['nr_sectors'],  # Use sectors as size
                    'sector': dblock['sector'],
                    'flags_str': "[none]",
                    'blk_operation': dblock['operation']
                }
                
                self.json_output.append(json_data)
                output += f"{int(timestamp)} [none] {dblock['pid']} {dblock['comm']} UNKNOWN 0 {dblock['nr_sectors']} {dblock['sector']} [none] {dblock['operation']}\n"
        
        # Finally, add unmatched VFS operations
        matched_vfs = set()
        for entry in self.json_output:
            if entry['op_name'] != "[none]":  # This is a matched VFS entry
                # Create a tuple of identifying information to track which VFS ops we've used
                vfs_key = (entry['pid'], entry['op_name'], entry['filename'], entry['inode'])
                matched_vfs.add(vfs_key)
        
        for dvfs in self.data_vfs:
            vfs_key = (dvfs['pid'], dvfs['op_name'], dvfs['filename'], dvfs['inode'])
            if vfs_key not in matched_vfs:
                timestamp = float(dvfs['timestamp'])
                
                json_data = {
                    'timestamp': int(timestamp),
                    'op_name': dvfs['op_name'],
                    'pid': dvfs['pid'],
                    'comm': dvfs['comm'],
                    'filename': dvfs['filename'],
                    'inode': dvfs['inode'],
                    'size_val': dvfs['size_val'],
                    'sector': "0",  # No matching block operation
                    'flags_str': dvfs['flags_str'],
                    'blk_operation': "[none]"
                }
                
                self.json_output.append(json_data)
                output += f"{int(timestamp)} {dvfs['op_name']} {dvfs['pid']} {dvfs['comm']} {dvfs['filename']} {dvfs['inode']} {dvfs['size_val']} 0 {dvfs['flags_str']} [none]\n"
        
        self.json_output.sort(key=lambda x: x['timestamp'])
        
        output = "timestamp vfs_op_name pid comm filename inode size_val sector flags_str blk_operation\n"
        for entry in self.json_output:
            output += f"{entry['timestamp']} {entry['op_name']} {entry['pid']} {entry['comm']} {entry['filename']} {entry['inode']} {entry['size_val']} {entry['sector']} {entry['flags_str']} {entry['blk_operation']}\n"
        return output
    
    def _write_output(self, output):
        try:
            outfile = open(self.output_file, 'w', buffering=1)
            outfile.write(output)
            outfile.close()

            with open(self.output_json_file, 'w') as json_file:
                json.dump(self.json_output, json_file, indent=2)
        except Exception as e:
            print(f"Error: {e}")

    def _find_optimal_time_window(self):
        windows_to_test = [
            1_000_000,      # 1ms
            5_000_000,      # 5ms
            10_000_000,     # 10ms
            50_000_000,     # 50ms
            100_000_000,    # 100ms
            500_000_000,    # 500ms
            1_000_000_000   # 1s
        ]
        
        results = {}
        
        direct_io_ops = [op for op in self.data_vfs 
                        if 'O_DIRECT' in op.get('flags_str', '')]
        
        if self.verbose:
            print(f"Analyzing {len(direct_io_ops)} direct I/O operations")
        
        for window in windows_to_test:
            matches = 0
            false_positives = 0
            
            for vfs_op in direct_io_ops:
                vfs_timestamp = float(vfs_op['timestamp'])
                vfs_pid = vfs_op['pid']
                vfs_size = int(vfs_op.get('size_val', 0))
                
                # Find block operations within this time window
                matching_blocks = [
                    block for block in self.data_block
                    if block['pid'] == vfs_pid
                    and vfs_timestamp <= float(block['timestamp']) <= vfs_timestamp + window
                ]
                
                if matching_blocks:
                    matches += 1
                    
                    # Calculate total block size for WRITE/READ operations
                    if vfs_op['op_name'] in ['READ', 'WRITE'] and vfs_size > 0:
                        total_block_bytes = sum(
                            int(block['nr_sectors']) * 512 
                            for block in matching_blocks
                        )
                        
                        # If sizes differ by more than 20%, might be a false positive
                        if not (0.8 <= total_block_bytes / vfs_size <= 1.2):
                            false_positives += 1
            
            # Calculate match rate and false positive rate
            match_rate = matches / len(direct_io_ops) if direct_io_ops else 0
            false_positive_rate = false_positives / matches if matches else 0
            
            results[window] = {
                'window_ms': window / 1_000_000,
                'matches': matches,
                'match_rate': match_rate,
                'false_positives': false_positives,
                'false_positive_rate': false_positive_rate,
                'score': match_rate * (1 - false_positive_rate)  # Combined score
            }
            if self.verbose:
                print(f"Window {window/1_000_000}ms: {match_rate:.2f} match rate, "
                    f"{false_positive_rate:.2f} false positive rate, "
                    f"Score: {match_rate * (1 - false_positive_rate):.3f}")
        
        # Find the window with the best score
        best_window = max(results.items(), key=lambda x: x[1]['score'])
        if self.verbose:
            print(f"Optimal time window: {best_window[1]['window_ms']}ms with score {best_window[1]['score']:.3f}")
        if(self.time_window != int(best_window[1]['window_ms'])*1000000):
            logger("info",f"Try running with flag -tw: {int(best_window[1]['window_ms'])}000000 for better results")
        
        self.time_window = int(best_window[1]['window_ms']) * 1_000_000

    def _adaptive_time_window(self, vfs_op):
        base_window = self.time_window
        
        op_type = vfs_op['op_name']
        is_direct = 'O_DIRECT' in vfs_op.get('flags_str', '')
        
        if op_type == 'READ':
            if is_direct:
                return base_window * 0.5  # Direct reads are faster
            else:
                return base_window * 2  # Buffered reads may have caching effects
        
        elif op_type == 'WRITE':
            if is_direct:
                return base_window  # Direct writes fairly predictable
            else:
                return base_window * 10  # Buffered writes can be delayed significantly
        
        elif op_type in ['OPEN', 'CLOSE']:
            return base_window * 5  # Metadata operations have variable timing
        
        return base_window

    def run(self):
        logger("info", "Mapping block-level traces to file-level traces..")
        self._parse_block_log()
        self._parse_vfs_log()
        output = self._find_matching_pid()
        self._write_output(output)
        logger("info", "Mapping completed. Output written to: " + self.output_file)