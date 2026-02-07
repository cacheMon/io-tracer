"""
FlagMapper - Maps kernel-level I/O flags to human-readable names.

This module provides functionality to decode and format various flags used in
Linux kernel I/O operations, including:
- File open flags (O_RDONLY, O_WRONLY, O_RDWR, etc.)
- Block device operation types (READ, WRITE, FLUSH, etc.)
- File system operation types (open, close, read, write, etc.)

The flags are mapped according to Linux kernel definitions:
- https://github.com/analogdevicesinc/linux/blob/main/include/linux/blk_types.h
- https://elixir.bootlin.com/linux/v6.14.6/source/include/linux/blk_types.h

Example:
    mapper = FlagMapper()
    flags = mapper.format_fs_flags(0o00000200 | 0o00000100)  # O_CREAT | O_EXCL
    # Returns: "O_CREAT|O_EXCL"
"""


class FlagMapper:
    """
    A utility class for mapping Linux kernel I/O flags to human-readable names.
    
    This class provides methods to decode:
    - File system flags (open flags, access modes)
    - Block device operation types
    - File system operation types
    """
    
    def __init__(self):
        """
        Initialize the FlagMapper with flag mappings.
        
        Initializes three mapping dictionaries:
        - flag_fs_map: Maps open() flags to their names
        - op_block_types: Maps block device operation codes to names
        - op_fs_types: Maps file system operation codes to names
        """
        # File open flags - https://github.com/analogdevicesinc/linux/blob/main/include/linux/blk_types.h#L370
        self.flag_fs_map = {
            0o00000000: "O_RDONLY",
            0o00000001: "O_WRONLY", 
            0o00000002: "O_RDWR",
            0o00000100: "O_CREAT",
            0o00000200: "O_EXCL",
            0o00000400: "O_NOCTTY",
            0o00001000: "O_TRUNC",
            0o00002000: "O_APPEND",
            0o00004000: "O_NONBLOCK",
            0o00010000: "O_DSYNC",
            0o00040000: "O_DIRECT",
            0o00100000: "O_LARGEFILE",
            0o00200000: "O_DIRECTORY",
            0o00400000: "O_NOFOLLOW",
            0o01000000: "O_NOATIME",
            0o02000000: "O_CLOEXEC",
            0o04010000: "O_SYNC",
            0o010000000: "O_PATH",
            0o020200000: "O_TMPFILE"
        }

        # Block device operation types - https://elixir.bootlin.com/linux/v6.14.6/source/include/linux/blk_types.h#L312
        self.op_block_types = {
            0: "REQ_OP_READ",
            1: "REQ_OP_WRITE",
            2: "REQ_OP_FLUSH",
            3: "REQ_OP_DISCARD",
            5: "REQ_OP_SECURE_ERASE",
            7: "REQ_OP_ZONE_APPEND",
            9: "REQ_OP_WRITE_ZEROES",
            10: "REQ_OP_ZONE_OPEN",
            11: "REQ_OP_ZONE_CLOSE",
            12: "REQ_OP_ZONE_FINISH",
            13: "REQ_OP_ZONE_RESET",
            15: "REQ_OP_ZONE_RESET_ALL",
            34: "REQ_OP_DRV_IN",
            35: "REQ_OP_DRV_OUT",
            36: "REQ_OP_LAST"
        }

        # File system operation types
        self.op_fs_types = {
            1: "READ",
            2: "WRITE",
            3: "OPEN",
            4: "CLOSE",
            5: "FSYNC",
            6: "MMAP",
            7: "MUNMAP",
            8: "GETATTR",
            9: "SETATTR",
            10: "CHDIR",
            11: "READDIR",
            12: "UNLINK",
            13: "TRUNCATE",
            14: "SYNC",
            15: "RENAME",
            16: "MKDIR",
            17: "RMDIR",
            18: "LINK",
            19: "SYMLINK",
            20: "FALLOCATE",
            21: "SENDFILE"
        }

        # mmap protection flags
        self.mmap_prot_flags = {
            0x0: "PROT_NONE",
            0x1: "PROT_READ",
            0x2: "PROT_WRITE",
            0x4: "PROT_EXEC"
        }

        # mmap mapping flags
        self.mmap_map_flags = {
            0x01: "MAP_SHARED",
            0x02: "MAP_PRIVATE",
            0x10: "MAP_FIXED",
            0x20: "MAP_ANONYMOUS",
            0x0100: "MAP_GROWSDOWN",
            0x0800: "MAP_DENYWRITE",
            0x1000: "MAP_EXECUTABLE",
            0x2000: "MAP_LOCKED",
            0x4000: "MAP_NORESERVE",
            0x8000: "MAP_POPULATE",
            0x10000: "MAP_NONBLOCK",
            0x20000: "MAP_STACK",
            0x40000: "MAP_HUGETLB"
        }

        # fallocate mode flags
        self.fallocate_flags = {
            0x01: "FALLOC_FL_KEEP_SIZE",
            0x02: "FALLOC_FL_PUNCH_HOLE",
            0x08: "FALLOC_FL_COLLAPSE_RANGE",
            0x10: "FALLOC_FL_ZERO_RANGE",
            0x20: "FALLOC_FL_INSERT_RANGE",
            0x40: "FALLOC_FL_UNSHARE_RANGE"
        }

    def format_block_operation(self, flags):
        """
        Format a block device operation code to its name.
        
        Args:
            flags: Integer representing the block operation type.
            
        Returns:
            str: The operation name (e.g., "REQ_OP_READ") or "[UNKNOWN_OP(X)]" if unknown.
        """
        result = [self.op_block_types.get(flags, f"[UNKNOWN_OP({flags})]")]
        return "|".join(result) if result else "NO_FLAGS"

    def format_fs_flags(self, flags):
        """
        Format file system open flags to a human-readable string.
        
        Decodes the access mode (O_RDONLY, O_WRONLY, O_RDWR) and combines it
        with any additional flags present.
        
        Args:
            flags: Integer representing the open() flags.
            
        Returns:
            str: Pipe-separated string of flag names (e.g., "O_RDWR|O_CREAT|O_TRUNC")
                 or "NO_FLAGS" if no flags are set.
                 
        Example:
            >>> mapper.format_fs_flags(0o00000202)
            'O_RDWR|O_CREAT'
        """
        # Handle access mode specially
        access_mode = flags & 0o3  # mask with 0b11 (3 in decimal)
        access_str = None
        if access_mode == 0o0:
            access_str = "O_RDONLY"
        elif access_mode == 0o1:
            access_str = "O_WRONLY"
        elif access_mode == 0o2:
            access_str = "O_RDWR"
            
        result = []
        if access_str:
            result.append(access_str)
            
        # Check for other flags (skip access mode flags already handled)
        for flag, name in self.flag_fs_map.items():
            if name in ["O_RDONLY", "O_WRONLY", "O_RDWR"]:
                continue
                
            # Special handling for O_SYNC because it includes O_DSYNC
            if name == "O_SYNC" and flags & 0o04010000:
                result.append(name)
                continue
                
            # Special handling for O_TMPFILE because it includes O_DIRECTORY
            if name == "O_TMPFILE" and (flags & 0o020200000) == 0o020200000:
                result.append(name)
                # Remove O_DIRECTORY if it's already in the list since it's part of O_TMPFILE
                if "O_DIRECTORY" in result:
                    result.remove("O_DIRECTORY")
                continue
                
            # Handle all other regular flags
            if name not in ["O_SYNC", "O_TMPFILE"] and flags & flag:
                result.append(name)
        
        return "|" .join(result) if result else "NO_FLAGS"
    
    def decode_mmap_flags(self, flags):
        """
        Decode mmap protection and mapping flags.
        
        The flags parameter contains both protection (lower 16 bits) and
        mapping flags (upper 16 bits) packed together.
        
        Args:
            flags: Integer with prot in lower 16 bits, map flags in upper 16 bits.
            
        Returns:
            str: Human-readable string like "PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS"
        """
        prot = flags & 0xFFFF
        map_flags = (flags >> 16) & 0xFFFF
        
        # Decode protection flags
        prot_result = []
        if prot == 0:
            prot_result.append("PROT_NONE")
        else:
            for flag, name in self.mmap_prot_flags.items():
                if flag != 0 and prot & flag:
                    prot_result.append(name)
        
        # Decode mapping flags
        map_result = []
        for flag, name in self.mmap_map_flags.items():
            if map_flags & flag:
                map_result.append(name)
        
        prot_str = "|".join(prot_result) if prot_result else "NO_PROT"
        map_str = "|".join(map_result) if map_result else "NO_MAP"
        
        return f"{prot_str},{map_str}"
    
    def decode_fallocate_flags(self, flags):
        """
        Decode fallocate mode flags.
        
        Args:
            flags: Integer representing fallocate mode flags.
            
        Returns:
            str: Pipe-separated string of flag names or "NO_FLAGS".
        """
        result = []
        for flag, name in self.fallocate_flags.items():
            if flags & flag:
                result.append(name)
        
        return "|".join(result) if result else "NO_FLAGS"
    
    def format_block_ops(self, flag: str):
        """
        Normalize block operation strings to simple read/write format.
        
        Takes an operation string and returns a simplified "read" or "write"
        representation based on the first character.
        
        Args:
            flag: String representing the operation (e.g., "REQ_OP_READ").
            
        Returns:
            str: "read", "write", or the original flag if it doesn't match.
            
        Example:
            >>> mapper.format_block_ops("REQ_OP_READ")
            'read'
            >>> mapper.format_block_ops("REQ_OP_WRITE")
            'write'
        """
        first_char = flag[0]
        if first_char == "W":
            return "write"
        elif first_char == "R":
            return "read"
        else:
            return flag
