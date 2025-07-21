import os
import time
import datetime
import tarfile

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