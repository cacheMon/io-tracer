import psutil
import time
import threading
import os
from pathlib import Path

class OverheadMeasurement:
    """
    Systematic measurement of tracer overhead including:
    1. CPU utilization (system-wide and per-process)
    2. Application slowdown (benchmark comparison)
    3. Memory usage impact
    4. I/O throughput impact
    """
    
    def __init__(self, output_dir="overhead_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.measurements = {
            'cpu_usage': [],
            'memory_usage': [],
            'disk_io': [],
            'network_io': [],
            'process_stats': []
        }
        self.monitoring = False
        
    def start_system_monitoring(self, interval=0.1):
        """Start continuous system monitoring in background thread"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_system, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
    def stop_system_monitoring(self):
        """Stop system monitoring"""
        self.monitoring = False
        if hasattr(self, 'monitor_thread'):
            self.monitor_thread.join(timeout=1)
    
    def _monitor_system(self, interval):
        """Internal method for continuous system monitoring"""
        while self.monitoring:
            try:
                # CPU usage per core and overall
                cpu_percent = psutil.cpu_percent(percpu=True)
                cpu_overall = psutil.cpu_percent()
                
                # Memory usage
                memory = psutil.virtual_memory()
                
                # Disk I/O
                disk_io = psutil.disk_io_counters()
                
                # Network I/O
                net_io = psutil.net_io_counters()
                
                timestamp = time.time()
                
                self.measurements['cpu_usage'].append({
                    'timestamp': timestamp,
                    'cpu_overall': cpu_overall,
                    'cpu_per_core': cpu_percent,
                    'load_avg': os.getloadavg() if hasattr(os, 'getloadavg') else None
                })
                
                self.measurements['memory_usage'].append({
                    'timestamp': timestamp,
                    'total': memory.total,
                    'available': memory.available,
                    'used': memory.used,
                    'percent': memory.percent
                })
                
                if disk_io:
                    self.measurements['disk_io'].append({
                        'timestamp': timestamp,
                        'read_bytes': disk_io.read_bytes,
                        'write_bytes': disk_io.write_bytes,
                        'read_count': disk_io.read_count,
                        'write_count': disk_io.write_count
                    })
                
                if net_io:
                    self.measurements['network_io'].append({
                        'timestamp': timestamp,
                        'bytes_sent': net_io.bytes_sent,
                        'bytes_recv': net_io.bytes_recv,
                        'packets_sent': net_io.packets_sent,
                        'packets_recv': net_io.packets_recv
                    })
                    
            except Exception as e:
                print(f"Monitoring error: {e}")
                
            time.sleep(interval)
    
    def monitor_process(self, pid):
        """Monitor specific process (like your tracer)"""
        try:
            process = psutil.Process(pid)
            process_info = {
                'timestamp': time.time(),
                'pid': pid,
                'name': process.name(),
                'cpu_percent': process.cpu_percent(),
                'memory_info': process.memory_info()._asdict(),
                'memory_percent': process.memory_percent(),
                'num_threads': process.num_threads(),
                'io_counters': process.io_counters()._asdict() if process.io_counters() else None,
                'status': process.status()
            }
            self.measurements['process_stats'].append(process_info)
            return process_info
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            print(f"Process monitoring error: {e}")
            return None
