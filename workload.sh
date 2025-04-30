#!/bin/bash

# Create a test file with sequential block writes
dd if=/dev/urandom of=/tmp/blocktest bs=4M count=64 oflag=direct && sync && \
# Random block reads (simulates database random access)
for i in {1..30}; do 
  # Random reads with different block sizes (4K, 8K, 16K, 32K - common database page sizes)
  bs=$((4096 * 2**($i % 4)))
  dd if=/tmp/blocktest of=/dev/null bs=$bs count=10 skip=$(($i * 13 % 1000)) iflag=direct && \
  # Sequential reads (simulates table scans)
  dd if=/tmp/blocktest of=/dev/null bs=1M count=10 skip=$(($i % 50)) iflag=direct && \
  # Write to different offsets (simulates database updates/writes)
  dd if=/dev/urandom of=/tmp/blocktest bs=4K count=1 seek=$(($i * 25 % 1000)) conv=notrunc oflag=direct && \
  # Flush changes to disk
  sync
done && \
# Clean up
rm /tmp/blocktest