import subprocess
import sys
from pathlib import Path


class BenchmarkSuite:
    """Collection of benchmarks to measure application slowdown"""
    
    def __init__(self, output_dir="benchmark_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
    def run_io_intensive_benchmark(self, duration=30):
        """I/O intensive benchmark - measures file operations"""
        benchmark_script = f"""
import time
import os
import tempfile
import random

def io_benchmark(duration):
    start_time = time.time()
    operations = 0
    bytes_written = 0
    bytes_read = 0

    directory_path = "./bin"
    os.makedirs(directory_path, exist_ok=True)
    
    while time.time() - start_time < duration:
        # Write test
        filename = os.path.join(directory_path, f"test_{{operations}}.txt")
        data = b"x" * random.randint(1024, 8192)  # 1-8KB chunks
        
        with open(filename, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        bytes_written += len(data)
        
        # Read test
        with open(filename, 'rb') as f:
            read_data = f.read()
        bytes_read += len(read_data)
        
        # Delete test
        os.unlink(filename)
        operations += 1
    os.remove(directory_path)
    
    actual_duration = time.time() - start_time
    return {{
        'duration': actual_duration,
        'operations': operations,
        'ops_per_second': operations / actual_duration,
        'bytes_written': bytes_written,
        'bytes_read': bytes_read,
        'write_throughput_mbps': (bytes_written / (1024*1024)) / actual_duration,
        'read_throughput_mbps': (bytes_read / (1024*1024)) / actual_duration
    }}

if __name__ == "__main__":
    result = io_benchmark({duration})
    print(f"BENCHMARK_RESULT:{{result}}")
"""
        # Run benchmark and capture output
        try:
            result = subprocess.run([sys.executable, '-c', benchmark_script], 
                                  capture_output=True, text=True, timeout=duration*2)
            
            # Parse result from output
            for line in result.stdout.split('\n'):
                if line.startswith('BENCHMARK_RESULT:'):
                    return eval(line.split(':', 1)[1])
                    
        except Exception as e:
            print(f"Benchmark error: {e}")
            return None
    
    def run_cpu_intensive_benchmark(self, duration=30):
        """CPU intensive benchmark - prime number calculation"""
        benchmark_script = f"""
import time
import math

def cpu_benchmark(duration):
    start_time = time.time()
    primes_found = 0
    number = 2
    
    def is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(math.sqrt(n)) + 1):
            if n % i == 0:
                return False
        return True
    
    while time.time() - start_time < duration:
        if is_prime(number):
            primes_found += 1
        number += 1
    
    actual_duration = time.time() - start_time
    return {{
        'duration': actual_duration,
        'numbers_checked': number - 2,
        'primes_found': primes_found,
        'checks_per_second': (number - 2) / actual_duration
    }}

if __name__ == "__main__":
    result = cpu_benchmark({duration})
    print(f"BENCHMARK_RESULT:{{result}}")
"""
        
        try:
            result = subprocess.run([sys.executable, '-c', benchmark_script], 
                                  capture_output=True, text=True, timeout=duration*2)
            
            for line in result.stdout.split('\n'):
                if line.startswith('BENCHMARK_RESULT:'):
                    return eval(line.split(':', 1)[1])
                    
        except Exception as e:
            print(f"CPU benchmark error: {e}")
            return None