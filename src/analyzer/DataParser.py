import gc
import tarfile
import pandas as pd
import numpy as np
from pathlib import Path
from typing import List, Dict, Any
from tqdm import tqdm


class DataParser:
    
    def __init__(self, raw_file: str):
        self.raw_file = raw_file
        self.tar = None
        self.block_data = []
        self.vfs_data = []
    
    def _parse_block_log(self):
        block_members = [m for m in self.tar.getmembers() if m.name.startswith('block/log') and m.isfile()]
        print(f"Parsing {len(block_members)} block log files...")
        
        count = 0
        chunk_size = 10000  # Process in chunks to manage memory
        
        lba_zero = []

        # Progress bar for files
        for member in tqdm(block_members, desc="Processing block log files", unit="file"):
            count += 1
            # if count > 1:
            #     break
                        
            file_obj = self.tar.extractfile(member)
            if file_obj:
                content = file_obj.read().decode('utf-8')
                lines = content.strip().split('\n')
                
                chunk = []
                # Progress bar for lines within each file
                for line_number, line in enumerate(tqdm(lines, desc=f"Processing lines in file {count}", unit="line", leave=False), 1):
                    if line_number == 1:  # Skip header
                        continue
                    line = line.strip()
                    if line:  
                        parts = line.split()
                        if (parts[4] == 0 and parts[5] == 0) or (parts[4] == '0' and parts[5] == '0'):
                            lba_zero.append(line)
                        if len(parts) >= 6:  
                            chunk.append({
                                'timestamp': parts[0],
                                'pid': parts[1],
                                'comm': parts[3],
                                'sector': parts[4], 
                                'nr_sectors': parts[5],
                                'operation': parts[6],
                            })
                            
                            # Process chunk when it reaches size limit
                            if len(chunk) >= chunk_size:
                                self.block_data.extend(chunk)
                                chunk = []
                
                # Add remaining items
                if chunk:
                    self.block_data.extend(chunk)
                
                # Force garbage collection
                del content, lines
                gc.collect()

    def _parse_vfs_log(self):
        vfs_members = [m for m in self.tar.getmembers() if m.name.startswith('vfs/log') and m.isfile()]
        print(f"Parsing {len(vfs_members)} VFS log files...")
        
        count = 0
        chunk_size = 10000
        
        # Progress bar for files
        for member in tqdm(vfs_members, desc="Processing VFS log files", unit="file"):
            count += 1
            # if count > 1:
            #     break
            
            file_obj = self.tar.extractfile(member)
            if file_obj:
                content = file_obj.read().decode('utf-8')
                lines = content.strip().split('\n')
                
                chunk = []
                # Progress bar for lines within each file
                for line_number, line in enumerate(tqdm(lines, desc=f"Processing lines in file {count}", unit="line", leave=False), 1):
                    if line_number == 1:  # Skip header
                        continue
                    line = line.strip()
                    if line:  
                        parts = line.split()
                        if len(parts) >= 8:  
                            chunk.append({
                                'timestamp': parts[0], 
                                'op_name': parts[1], 
                                'pid': parts[2], 
                                'comm': parts[3], 
                                'filename': parts[4], 
                                'inode': parts[5], 
                                'size_val': parts[6], 
                                'flags_str': parts[7],
                            })
                            
                            if len(chunk) >= chunk_size:
                                self.vfs_data.extend(chunk)
                                chunk = []
                
                if chunk:
                    self.vfs_data.extend(chunk)
                
                del content, lines
                gc.collect()
    
    def _optimize_block_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        # Optimize data types
        df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
        df['pid'] = pd.to_numeric(df['pid'], errors='coerce', downcast=None)
        df['sector'] = pd.to_numeric(df['sector'], errors='coerce', downcast=None)
        df['nr_sectors'] = pd.to_numeric(df['nr_sectors'], errors='coerce', downcast=None)
        
        # Calculate derived columns
        df['io_size_bytes'] = df['nr_sectors'] * 512
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='ns')
        
        # Convert strings to categories to save memory
        df['comm'] = df['comm'].astype('category')
        df['operation'] = df['operation'].astype('category')
        
        return df
    
    def _optimize_vfs_dataframe(self, df: pd.DataFrame) -> pd.DataFrame:
        """Optimize VFS DataFrame data types."""
        # Optimize data types
        df['timestamp'] = pd.to_numeric(df['timestamp'], errors='coerce')
        df['pid'] = pd.to_numeric(df['pid'], errors='coerce', downcast='integer')
        df['inode'] = pd.to_numeric(df['inode'], errors='coerce', downcast='integer')
        df['size_val'] = pd.to_numeric(df['size_val'], errors='coerce')
        df['datetime'] = pd.to_datetime(df['timestamp'], unit='ns')
        
        # Convert to categories
        df['op_name'] = df['op_name'].astype('category')
        df['comm'] = df['comm'].astype('category')
        df['filename'] = df['filename'].astype('category')
        df['flags_str'] = df['flags_str'].astype('category')
        
        return df
    
    def parse(self) -> tuple[pd.DataFrame, pd.DataFrame]:
        print("Opening tar file...")
        self.tar = tarfile.open(self.raw_file, 'r:gz')
        
        block_df = None
        vfs_df = None
        
        try:
            self._parse_block_log()
            self._parse_vfs_log()
            print("Finished parsing tar file")
            
            # Create DataFrames with optimized dtypes
            if self.block_data:
                print("Creating block DataFrame...")
                block_df = pd.DataFrame(self.block_data)
                block_df = self._optimize_block_dataframe(block_df)
                
            if self.vfs_data:
                print("Creating VFS DataFrame...")
                vfs_df = pd.DataFrame(self.vfs_data)
                vfs_df = self._optimize_vfs_dataframe(vfs_df)
                
            # Clear raw data to free memory
            self.block_data = []
            self.vfs_data = []
            gc.collect()
            
            print("DataFrames prepared successfully")
            
        finally:
            if self.tar:
                self.tar.close()
        
        return block_df, vfs_df