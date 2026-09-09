import threading
import queue
import time
import logging
from typing import Dict, Any, Callable, List, Optional
from collections import defaultdict

from .database import DatabaseManager
from .models import EventLog

logger = logging.getLogger(__name__)

class EventBus:
    """Asynchronous, thread-safe, research-grade event pipeline."""
    
    def __init__(self, db_manager: DatabaseManager = None):
        self.db = db_manager
        self.subscribers: Dict[str, List[Callable]] = defaultdict(list)
        self._queue: queue.Queue = queue.Queue(maxsize=100000)
        self._lock = threading.RLock()
        self._worker_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        
    def start(self):
        with self._lock:
            if self._worker_thread is None or not self._worker_thread.is_alive():
                self._stop_event.clear()
                self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="EventBusWorker")
                self._worker_thread.start()

    def stop(self):
        self._stop_event.set()
        if self._worker_thread:
            self._worker_thread.join(timeout=2.0)
            self._worker_thread = None

    def subscribe(self, event_type: str, callback: Callable[[Dict[str, Any]], None]):
        """Subscribe a callback to a specific event type, or '*' for all."""
        with self._lock:
            self.subscribers[event_type].append(callback)

    def publish(self, source: str, event_type: str, payload: Dict[str, Any], 
                experiment_id: str = None, severity: str = "INFO", 
                correlation_id: str = None, persist: bool = True):
        """Publish an event to the bus."""
        event = {
            "timestamp": time.time(),
            "source": source,
            "event_type": event_type,
            "severity": severity,
            "experiment_id": experiment_id,
            "correlation_id": correlation_id,
            "payload": payload,
            "persist": persist
        }
        
        try:
            self._queue.put_nowait(event)
        except queue.Full:
            logger.error("EventBus queue full; dropping event %s", event_type)

    def _worker_loop(self):
        db_batch = []
        last_flush = time.time()
        
        while not self._stop_event.is_set():
            try:
                event = self._queue.get(timeout=0.5)
            except queue.Empty:
                if db_batch and time.time() - last_flush > 1.0:
                    self._flush_db(db_batch)
                    db_batch = []
                    last_flush = time.time()
                continue
            
            # Dispatch to subscribers
            self._dispatch(event)
            
            if event.get("persist") and self.db:
                db_batch.append(event)
                
            if len(db_batch) >= 100 or (time.time() - last_flush > 1.0 and db_batch):
                self._flush_db(db_batch)
                db_batch = []
                last_flush = time.time()
                
            self._queue.task_done()
            
        # Final flush
        if db_batch:
            self._flush_db(db_batch)

    def _dispatch(self, event: Dict[str, Any]):
        evt_type = event["event_type"]
        subs = []
        with self._lock:
            subs.extend(self.subscribers.get(evt_type, []))
            subs.extend(self.subscribers.get("*", []))
            
        for cb in subs:
            try:
                cb(event)
            except Exception as e:
                logger.error("Error in event subscriber for %s: %s", evt_type, e)

    def _flush_db(self, batch: List[Dict[str, Any]]):
        if not self.db:
            return
            
        try:
            with self.db.session_scope() as session:
                for e in batch:
                    db_event = EventLog(
                        experiment_id=e["experiment_id"],
                        timestamp=e["timestamp"],
                        source=e["source"],
                        event_type=e["event_type"],
                        severity=e["severity"],
                        correlation_id=e["correlation_id"],
                        payload=e["payload"]
                    )
                    session.add(db_event)
        except Exception as e:
            logger.error("Failed to persist event batch: %s", e)
