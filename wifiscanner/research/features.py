from typing import List, Dict, Any, Optional

from .benchmark import DetectorInterface

class WatchdogDetectorAdapter(DetectorInterface):
    """Wraps the Watchdog IDS inside the new research benchmark framework."""
    def __init__(self, config=None):
        super().__init__(config)
        from wifiscanner.defense import Watchdog
        
        self.watchdog = Watchdog(
            window_s=self.config.get("window_s", 10.0),
            flood_frames=self.config.get("flood_frames", 5),
            cooldown_s=self.config.get("cooldown_s", 30.0),
            sensitivity=self.config.get("sensitivity", "medium"),
            known_bssids=self.config.get("known_bssids", frozenset())
        )
        self.watchdog.alerts.clear() # clear list
        self.name = "WatchdogDetector"
        self._last_alert_len = 0
        
    def initialize(self):
        self.watchdog.alerts.clear()
        self._last_alert_len = 0
        
    def process_event(self, event):
        # The Watchdog expects scapy frames directly.
        # This wrapper expects the 'event' to contain a "frame" object (scapy)
        if "frame" not in event:
            return None
            
        self.watchdog.feed(event["frame"])
        
        if len(self.watchdog.alerts) > self._last_alert_len:
            # We got an alert
            new_alerts = self.watchdog.alerts[self._last_alert_len:]
            self._last_alert_len = len(self.watchdog.alerts)
            
            # Return the highest severity one as the result for this frame
            alert = new_alerts[-1]
            return {
                "alert": alert.kind,
                "confidence": alert.confidence,
                "detail": alert.detail
            }
        return None
        
    def finalize(self):
        return {
            "total_alerts": len(self.watchdog.alerts)
        }

class FeatureExtractor:
    """Reusable feature extraction framework for ML pipelines."""
    
    def __init__(self):
        self.features: List[str] = []
        
    def extract(self, raw_data: Any) -> Dict[str, float]:
        """Convert raw capture/packet data into a normalized feature vector."""
        raise NotImplementedError()
        
class FrameFeatureExtractor(FeatureExtractor):
    """Extracts ML-ready features from an 802.11 frame."""
    
    def __init__(self):
        super().__init__()
        self.features = [
            "frame_length", 
            "signal_dbm", 
            "noise_dbm", 
            "is_management", 
            "is_data", 
            "is_control",
            "has_radiotap",
            "delta_time_ms"
        ]
        self._last_time = None
        
    def extract(self, pkt: Any) -> Dict[str, float]:
        # 'pkt' is assumed to be a scapy packet, but we'll accept a dict for tests
        features = {f: 0.0 for f in self.features}
        
        if isinstance(pkt, dict):
            # Dict mode (for events/tests)
            features["frame_length"] = float(pkt.get("len", 0))
            features["signal_dbm"] = float(pkt.get("rssi", -100))
            features["noise_dbm"] = float(pkt.get("noise", -100))
            f_type = pkt.get("type", 0)
            if f_type == 0:
                features["is_management"] = 1.0
            elif f_type == 1:
                features["is_control"] = 1.0
            elif f_type == 2:
                features["is_data"] = 1.0
                
            ts = pkt.get("time", 0.0)
            if self._last_time is not None:
                features["delta_time_ms"] = (ts - self._last_time) * 1000.0
            self._last_time = ts
            
            features["has_radiotap"] = 1.0 if pkt.get("radiotap") else 0.0
            
        else:
            # Scapy mode (assuming it's a scapy Packet)
            features["frame_length"] = float(len(pkt))
            if pkt.haslayer("RadioTap"):
                features["has_radiotap"] = 1.0
                if hasattr(pkt["RadioTap"], "dBm_AntSignal"):
                    features["signal_dbm"] = float(pkt["RadioTap"].dBm_AntSignal)
                if hasattr(pkt["RadioTap"], "dBm_AntNoise"):
                    features["noise_dbm"] = float(pkt["RadioTap"].dBm_AntNoise)
                    
            if pkt.haslayer("Dot11"):
                f_type = pkt["Dot11"].type
                if f_type == 0:
                    features["is_management"] = 1.0
                elif f_type == 1:
                    features["is_control"] = 1.0
                elif f_type == 2:
                    features["is_data"] = 1.0
                    
            ts = float(pkt.time)
            if self._last_time is not None:
                features["delta_time_ms"] = (ts - self._last_time) * 1000.0
            self._last_time = ts
            
        return features

class MLDatasetProcessor:
    """Prepares extracted features for ML training/validation."""
    
    def __init__(self):
        pass
        
    def normalize_min_max(self, dataset: List[Dict[str, float]]) -> List[Dict[str, float]]:
        if not dataset:
            return []
            
        # Find min/max per feature
        mins = {k: float("inf") for k in dataset[0].keys()}
        maxs = {k: float("-inf") for k in dataset[0].keys()}
        
        for row in dataset:
            for k, v in row.items():
                if v < mins[k]: mins[k] = v
                if v > maxs[k]: maxs[k] = v
                
        # Normalize
        normalized = []
        for row in dataset:
            norm_row = {}
            for k, v in row.items():
                span = maxs[k] - mins[k]
                if span == 0:
                    norm_row[k] = 0.0
                else:
                    norm_row[k] = (v - mins[k]) / span
            normalized.append(norm_row)
            
        return normalized
