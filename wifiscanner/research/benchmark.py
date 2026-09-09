import logging
from typing import Dict, Any, List, Optional
from collections import defaultdict
import uuid

logger = logging.getLogger(__name__)

class DetectorInterface:
    """Base class for all research-grade custom detectors."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.detector_id = str(uuid.uuid4())
        self.name = self.__class__.__name__
        self.version = self.config.get("version", "1.0.0")

    def initialize(self):
        """Called before the detector starts processing."""
        pass

    def process_event(self, event: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Process an incoming event (e.g., from EventBus).
        Returns an Alert dictionary if an anomaly is detected, else None.
        """
        raise NotImplementedError("Detectors must implement process_event()")

    def finalize(self) -> Dict[str, Any]:
        """Called at the end of the experiment. Return summary metrics."""
        return {}


class BenchmarkFramework:
    """Framework to evaluate and compare detectors against a labeled dataset."""
    
    def __init__(self, dataset_labels: List[Dict[str, Any]]):
        """
        dataset_labels: A list of ground-truth labels retrieved from DatasetManager.
        Expects {"ref": "evt-123", "label": "True Positive", ...}
        """
        self.ground_truth = {l["ref"]: l["label"] for l in dataset_labels}
        self.results = defaultdict(dict)

    def evaluate_detector(self, detector: DetectorInterface, event_stream: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Runs the event stream through the detector and computes metrics."""
        logger.info(f"Benchmarking detector {detector.name}...")
        detector.initialize()
        
        start_time = time.time()
        
        tp = 0
        fp = 0
        tn = 0
        fn = 0
        processed = 0
        
        for event in event_stream:
            ref = event.get("id") or event.get("correlation_id")
            if not ref:
                continue
                
            actual = self.ground_truth.get(ref, "Negative")
            is_malicious = (actual in ("True Positive", "Attack", "Malicious", "Positive"))
            
            alert = detector.process_event(event)
            processed += 1
            
            if alert:
                if is_malicious:
                    tp += 1
                else:
                    fp += 1
            else:
                if is_malicious:
                    fn += 1
                else:
                    tn += 1
                    
        end_time = time.time()
        latency = end_time - start_time
        eps = processed / latency if latency > 0 else 0
        
        # Calculate ML metrics
        accuracy = (tp + tn) / processed if processed > 0 else 0
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        metrics = {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1_score": f1,
            "false_positive_rate": fpr,
            "latency_seconds": latency,
            "events_per_second": eps,
            "total_processed": processed,
            "detector_summary": detector.finalize()
        }
        
        self.results[detector.name] = metrics
        return metrics

import time
