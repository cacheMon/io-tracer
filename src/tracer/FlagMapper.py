class FlagMapper:
    def __init__(self):
        # https://github.com/analogdevicesinc/linux/blob/main/include/linux/blk_types.h#L370
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

        # https://elixir.bootlin.com/linux/v6.14.6/source/include/linux/blk_types.h#L312
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
            14: "SYNC"
        }

    def format_block_operation(self, flags):
        result = [self.op_block_types.get(flags, f"[UNKNOWN_OP({flags})]")]
        return "|".join(result) if result else "NO_FLAGS"

    def format_fs_flags(self, flags):
        # handle access mode specially
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
            
        # check for other flags
        # skip the access mode flags we already handled
        for flag, name in self.flag_fs_map.items():
            if name in ["O_RDONLY", "O_WRONLY", "O_RDWR"]:
                continue
                
            # special handling for O_SYNC because it includes O_DSYNC
            if name == "O_SYNC" and flags & 0o04010000:
                result.append(name)
                continue
                
            # specil handling for O_TMPFILE coz it includes O_DIRECTORY
            if name == "O_TMPFILE" and (flags & 0o020200000) == 0o020200000:
                result.append(name)
                # remove O_DIRECTORY if it's already in the list since it's part of O_TMPFILE
                if "O_DIRECTORY" in result:
                    result.remove("O_DIRECTORY")
                continue
                
            # handle all other regular flags
            if name not in ["O_SYNC", "O_TMPFILE"] and flags & flag:
                result.append(name)
        
        return "|".join(result) if result else "NO_FLAGS"
    
    def format_block_ops(self, flag:str):
        first_char = flag[0]
        if first_char == "W":
            return "write"
        elif first_char == "R":
            return "read"
        else:
            return flag