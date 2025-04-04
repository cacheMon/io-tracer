#!/bin/bash
echo "Testing VFS operations..."
echo "1. Testing read:" && cat /etc/passwd > /dev/null
echo "2. Testing write:" && echo "test data" > /tmp/vfs_test_file
echo "3. Testing open/close:" && touch /tmp/vfs_test_open
echo "4. Testing fsync:" && python3 -c "import os; fd = os.open('/tmp/fsync_test.txt', os.O_CREAT | os.O_RDWR); os.write(fd, b'test'); os.fsync(fd); os.close(fd)"
echo "5. Testing large read/write:" && dd if=/dev/zero of=/tmp/vfs_test_large bs=1M count=5 status=none
echo "Test complete!"