from pathlib import Path
import os
import time
import datetime
import tarfile
import gzip
import shutil
import hashlib

_HASH_CACHE: dict[str, str] = {}

def hash_component(name: str, keep_ext: bool = True, length: int = 12) -> str:
    if keep_ext and '.' in name and not name.startswith('.'):
        stem, ext = os.path.splitext(name)
        key = f"{stem}|{length}"
        if key not in _HASH_CACHE:
            _HASH_CACHE[key] = hashlib.sha256(stem.encode("utf-8")).hexdigest()[:length]
        return _HASH_CACHE[key] + ext
    else:
        key = f"{name}|{length}"
        if key not in _HASH_CACHE:
            _HASH_CACHE[key] = hashlib.sha256(name.encode("utf-8")).hexdigest()[:length]
        return _HASH_CACHE[key]

def hash_rel_path(rel: Path, keep_ext: bool = True, length: int = 12) -> Path:
    hashed_parts = [hash_component(p, keep_ext=keep_ext, length=length) for p in rel.parts]
    return Path(*hashed_parts)


def logger(error_scale,string, timestamp=False):
    timestamp_seconds = time.time()
    dt_object = datetime.datetime.fromtimestamp(timestamp_seconds)
    formatted_time = dt_object.strftime("%Y-%m-%d %H:%M:%S.%f")
    if error_scale == "warning":
        logo = "[WARN]"
    elif error_scale == "error":
        logo = "[ERROR]"
    elif error_scale == "info":
        logo = "[INFO]"
    else:
        logo = f"[{error_scale}]"

    if timestamp:
        timestamp_seconds = time.time()
        dt_object = datetime.datetime.fromtimestamp(timestamp_seconds)
        formatted_time = dt_object.strftime("%Y-%m-%d %H:%M:%S.%f")
        logo += f" [{formatted_time}]" 
    print(logo + " " + string)

def create_tar_gz(output_filename, files_to_archive):
    with tarfile.open(output_filename, "w:gz") as tar:
        for file_path in files_to_archive:
            tar.add(file_path, arcname=os.path.basename(file_path))
    logger("info", f"Created tar.gz archive: {output_filename}")

def compress_log(input_file):
    src = input_file
    dst = input_file + ".gz"
    with open(src, "rb") as f_in:
        with gzip.open(dst, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

    os.remove(input_file)