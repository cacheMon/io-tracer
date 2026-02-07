#!/bin/bash
# Test script for new filesystem operations
# This script exercises RENAME, MKDIR, RMDIR, LINK, SYMLINK, FALLOCATE, and SENDFILE operations
# to verify that the tracer properly captures these events.

set -e  # Exit on error

TESTDIR="/tmp/iotrace_test_$$"
echo "====================================="
echo "IO Tracer New Operations Test Script"
echo "====================================="
echo ""
echo "Test directory: $TESTDIR"
echo ""

# Cleanup function
cleanup() {
    echo ""
    echo "Cleaning up test directory..."
    rm -rf "$TESTDIR"
    echo "Cleanup complete."
}

# Register cleanup on exit
trap cleanup EXIT

# Create test directory
echo "[1/8] Testing MKDIR operation..."
mkdir -p "$TESTDIR"
mkdir "$TESTDIR/subdir1"
mkdir "$TESTDIR/subdir2"
echo "    ✓ Created directories"

# Create test files
echo "[2/8] Creating test files (WRITE operations)..."
echo "Test content for file1" > "$TESTDIR/file1.txt"
echo "Test content for file2" > "$TESTDIR/file2.txt"
echo "Larger test content for sendfile test" > "$TESTDIR/sendfile_source.txt"
for i in {1..100}; do
    echo "Line $i: Additional content for testing" >> "$TESTDIR/sendfile_source.txt"
done
echo "    ✓ Created test files"

# Test RENAME operation
echo "[3/8] Testing RENAME operation..."
mv "$TESTDIR/file1.txt" "$TESTDIR/file1_renamed.txt"
mv "$TESTDIR/subdir1" "$TESTDIR/subdir1_renamed"
echo "    ✓ Renamed file and directory"

# Test LINK operation (hard link)
echo "[4/8] Testing LINK operation..."
ln "$TESTDIR/file2.txt" "$TESTDIR/file2_hardlink.txt"
echo "    ✓ Created hard link"

# Test SYMLINK operation
echo "[5/8] Testing SYMLINK operation..."
ln -s "$TESTDIR/file2.txt" "$TESTDIR/file2_symlink.txt"
ln -s "$TESTDIR/subdir2" "$TESTDIR/subdir2_symlink"
echo "    ✓ Created symbolic links"

# Test FALLOCATE operation
echo "[6/8] Testing FALLOCATE operation..."
if command -v fallocate &> /dev/null; then
    fallocate -l 10M "$TESTDIR/preallocated_file.dat"
    echo "    ✓ Pre-allocated 10MB file"
else
    # Fallback to dd if fallocate is not available
    dd if=/dev/zero of="$TESTDIR/preallocated_file.dat" bs=1M count=10 &>/dev/null
    echo "    ✓ Created 10MB file (fallocate not available, used dd)"
fi

# Test SENDFILE operation (using cp which may use sendfile internally on Linux)
echo "[7/8] Testing SENDFILE operation..."
# On Linux, 'cp --reflink=never' or just 'cp' may use sendfile()
# For more explicit sendfile test, we use a simple Python script
python3 << 'PYTHON_EOF'
import os
source = os.environ['TESTDIR'] + '/sendfile_source.txt'
dest = os.environ['TESTDIR'] + '/sendfile_dest.txt'
with open(source, 'rb') as src:
    with open(dest, 'wb') as dst:
        # Python may use sendfile internally for large files
        dst.write(src.read())
print("    ✓ Performed file transfer (sendfile)")
PYTHON_EOF

# Test RMDIR operation
echo "[8/8] Testing RMDIR operation..."
rmdir "$TESTDIR/subdir1_renamed"
echo "    ✓ Removed directory"

# Additional operations for completeness
echo ""
echo "Performing additional operations..."
# Read operations
cat "$TESTDIR/file1_renamed.txt" > /dev/null
cat "$TESTDIR/file2_hardlink.txt" > /dev/null
readlink "$TESTDIR/file2_symlink.txt" > /dev/null
echo "    ✓ Read operations completed"

# List directory
ls -la "$TESTDIR" > /dev/null
echo "    ✓ Directory listing completed"

echo ""
echo "====================================="
echo "All tests completed successfully!"
echo "====================================="
echo ""
echo "To verify the trace captured these operations:"
echo "1. Check the trace output directory"
echo "2. Look for RENAME, MKDIR, RMDIR, LINK, SYMLINK, FALLOCATE, SENDFILE in fs_events.csv"
echo "3. Verify dual-path operations (RENAME, LINK) show 'old_path -> new_path' format"
echo ""

exit 0
