"""
PollingThread - Manages the perf buffer polling loop for eBPF events.

This module provides the PollingThread class which runs in a background
thread and continuously polls the perf buffer for captured eBPF events.

The polling thread is essential for processing events from the kernel
probes and calling the appropriate callback functions.

Example:
    poller = PollingThread(bpf_instance, polling_active=True)
    poller.create_thread()  # Start polling in background
"""

import time
from ..utility.utils import logger
import threading


class PollingThread:
    """
    Background thread for polling eBPF perf buffer events.
    
    This class manages a daemon thread that continuously polls
    the BPF perf buffer for available events and dispatches them
    to the appropriate callbacks.
    
    Attributes:
        bpf: BPF instance to poll for events
        polling_active: Boolean controlling polling loop
        
    Example:
        poller = PollingThread(bpf_instance, polling_active=True)
        poller.create_thread()
        # ... do other work ...
        poller.polling_active = False  # Stop polling
    """
    
    def __init__(self, bpf_instance, polling_active: bool):
        """
        Initialize the PollingThread.
        
        Args:
            bpf_instance: BPF instance with open perf buffers
            polling_active: Initial polling state (True to start polling)
        """
        self.bpf = bpf_instance
        self.polling_active = polling_active

    def run(self):
        """
        Main polling loop.
        
        Continuously polls the perf buffer with a timeout until
        polling_active is set to False. Handles exceptions gracefully
        with brief sleep to prevent busy-waiting on errors.
        """
        while self.polling_active:
            try:
                self.bpf.perf_buffer_poll(timeout=50)
            except Exception as e:
                logger("error", f"Error in polling thread: {e}")
                time.sleep(0.01)

    def create_thread(self) -> threading.Thread:
        """
        Start polling in a background daemon thread.
        
        Creates and starts a daemon thread running the polling loop.
        
        Returns:
            threading.Thread: The started thread object
        """
        poller = threading.Thread(target=self.run)
        poller.daemon = True
        poller.start()
        return poller
