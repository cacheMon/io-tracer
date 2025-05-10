#!/bin/bash

# Set up test files and directories
mkdir -p /tmp/vfs_test/{db,logs,cache}
cd /tmp/vfs_test

echo "Creating test files..."
# Create multiple test files with different sizes for diverse workloads
dd if=/dev/urandom of=db/large_file bs=8M count=128 oflag=direct 2>/dev/null
dd if=/dev/urandom of=db/medium_file bs=4M count=64 oflag=direct 2>/dev/null
dd if=/dev/urandom of=cache/small_file bs=1M count=32 oflag=direct 2>/dev/null

echo "Starting mixed workload simulation..."

# Run multiple parallel processes to generate concurrent I/O
{
  # Process 1: Database-like workload (random reads/writes, mixed block sizes)
  echo "Starting database workload simulation..."
  for i in {1..50}; do
    # Random reads with different block sizes (4K, 8K, 16K, 32K - common database page sizes)
    bs=$((4096 * 2**($i % 4)))
    dd if=db/large_file of=/dev/null bs=$bs count=25 skip=$(($RANDOM % 2000)) iflag=direct 2>/dev/null
    
    # Random writes (simulates database updates)
    dd if=/dev/urandom of=db/large_file bs=$bs count=5 seek=$(($RANDOM % 2000)) conv=notrunc oflag=direct 2>/dev/null
    
    # Database fsync operations
    sync db/large_file
    
    # Small delay to simulate real workload patterns
    sleep 0.01
  done
} &

{
  # Process 2: Log writing (sequential writes, fsync)
  echo "Starting log writing simulation..."
  for i in {1..100}; do
    # Append log entries (sequential writes)
    dd if=/dev/urandom of=logs/app_log bs=16K count=1 oflag=append conv=notrunc 2>/dev/null
    
    # Fsync after each write (common in logging systems)
    sync logs/app_log
    
    # Small delay
    sleep 0.05
  done
} &

{
  # Process 3: File copy operations (large sequential reads and writes)
  echo "Starting file copy simulation..."
  for i in {1..15}; do
    # Copy large file in chunks (sequential read+write)
    dd if=db/large_file of=cache/copy_$i bs=1M count=32 skip=$(($i % 10)) 2>/dev/null
    
    # Delayed delete to simulate file lifecycle
    if [ $i -gt 5 ]; then
      rm -f cache/copy_$(($i - 5)) 2>/dev/null
    fi
  done
} &

{
  # Process 4: Cache-like behavior (many small reads/writes)
  echo "Starting cache simulation..."
  for i in {1..200}; do
    # Random small reads (simulates cache lookups)
    dd if=cache/small_file of=/dev/null bs=4K count=1 skip=$(($RANDOM % 256)) iflag=direct 2>/dev/null
    
    # Random small writes (simulates cache updates)
    if [ $(($i % 10)) -eq 0 ]; then
      dd if=/dev/urandom of=cache/small_file bs=4K count=1 seek=$(($RANDOM % 256)) conv=notrunc oflag=direct 2>/dev/null
    fi
    
    # Occasional create/delete (simulates cache eviction)
    if [ $(($i % 20)) -eq 0 ]; then
      dd if=/dev/urandom of=cache/temp_$i bs=16K count=1 oflag=direct 2>/dev/null
      rm -f cache/temp_$(($i - 10)) 2>/dev/null
    fi
  done
} &

{
  # Process 5: Memory-mapped file operations
  echo "Starting mmap simulation..."
  for i in {1..20}; do
    # Create a temp file for mmap operations
    dd if=/dev/urandom of=cache/mmap_file_$i bs=1M count=8 oflag=direct 2>/dev/null
    
    # Use Python to perform mmap operations
    python3 -c "
import mmap
import os
import time
import random

with open('cache/mmap_file_$i', 'r+b') as f:
    # Memory map the file
    mm = mmap.mmap(f.fileno(), 0)
    
    # Perform random accesses
    for j in range(100):
        pos = random.randint(0, mm.size() - 1024)
        mm.seek(pos)
        data = mm.read(1024)
        
        # Occasional writes
        if j % 10 == 0:
            mm.seek(pos)
            mm.write(b'X' * 1024)
            mm.flush()
        
        time.sleep(0.01)
    
    mm.close()
" 2>/dev/null
    
    # Clean up
    rm -f cache/mmap_file_$i
  done
} &

{
  # Process 6: Metadata operations (creating/deleting many small files)
  echo "Starting metadata operation simulation..."
  mkdir -p cache/metadata_test
  
  for i in {1..200}; do
    # Create a small file
    dd if=/dev/urandom of=cache/metadata_test/file_$i bs=1K count=1 2>/dev/null
    
    # Rename some files
    if [ $(($i % 10)) -eq 0 ] && [ $i -gt 10 ]; then
      mv cache/metadata_test/file_$(($i - 10)) cache/metadata_test/renamed_file_$(($i - 10)) 2>/dev/null
    fi
    
    # Delete older files
    if [ $(($i % 20)) -eq 0 ] && [ $i -gt 20 ]; then
      rm -f cache/metadata_test/renamed_file_$(($i - 20)) 2>/dev/null
    fi
  done
} &

# Wait for all background processes to finish
wait

echo "Cleaning up test files..."
rm -rf /tmp/vfs_test
echo "Workload simulation completed!"