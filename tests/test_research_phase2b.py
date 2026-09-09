import unittest
from wifiscanner.research import (
    FeatureExtractor, FrameFeatureExtractor, MLDatasetProcessor,
    DetectorInterface, BenchmarkFramework
)

class DummyDetector(DetectorInterface):
    def process_event(self, event):
        # Extremely dumb threshold detector
        if event.get("rssi", -100) > -30:
            return {"alert": "High Power"}
        return None

class TestResearchPlatformPhase2b(unittest.TestCase):
    def test_feature_extraction(self):
        extractor = FrameFeatureExtractor()
        
        pkt1 = {"len": 128, "rssi": -65, "noise": -95, "type": 0, "radiotap": True, "time": 1000.0}
        pkt2 = {"len": 64, "rssi": -60, "noise": -92, "type": 2, "radiotap": True, "time": 1000.5}
        
        f1 = extractor.extract(pkt1)
        self.assertEqual(f1["frame_length"], 128.0)
        self.assertEqual(f1["is_management"], 1.0)
        self.assertEqual(f1["has_radiotap"], 1.0)
        self.assertEqual(f1["delta_time_ms"], 0.0)
        
        f2 = extractor.extract(pkt2)
        self.assertEqual(f2["is_data"], 1.0)
        self.assertEqual(f2["delta_time_ms"], 500.0)  # 0.5s difference

    def test_ml_normalization(self):
        proc = MLDatasetProcessor()
        data = [
            {"a": 10.0, "b": -100.0},
            {"a": 20.0, "b": -50.0},
            {"a": 30.0, "b": 0.0},
        ]
        
        norm = proc.normalize_min_max(data)
        
        self.assertEqual(norm[0]["a"], 0.0)
        self.assertEqual(norm[1]["a"], 0.5)
        self.assertEqual(norm[2]["a"], 1.0)
        
        self.assertEqual(norm[0]["b"], 0.0)
        self.assertEqual(norm[2]["b"], 1.0)

    def test_benchmark_framework(self):
        # Setup Ground Truth
        labels = [
            {"ref": "evt-1", "label": "Negative"},
            {"ref": "evt-2", "label": "True Positive"}, # Should fire alert
            {"ref": "evt-3", "label": "Negative"}
        ]
        
        bench = BenchmarkFramework(labels)
        
        # Setup Event stream
        events = [
            {"id": "evt-1", "rssi": -70},
            {"id": "evt-2", "rssi": -10}, # Attack event, triggers detector
            {"id": "evt-3", "rssi": -20}, # Benign event, triggers detector (False Positive)
        ]
        
        detector = DummyDetector()
        metrics = bench.evaluate_detector(detector, events)
        
        # TP = 1 (evt-2)
        # FP = 1 (evt-3)
        # TN = 1 (evt-1)
        # FN = 0
        
        self.assertEqual(metrics["total_processed"], 3)
        self.assertEqual(metrics["accuracy"], 2/3) # (1 TP + 1 TN) / 3
        self.assertEqual(metrics["precision"], 0.5) # 1 TP / (1 TP + 1 FP)
        self.assertEqual(metrics["recall"], 1.0) # 1 TP / (1 TP + 0 FN)

if __name__ == "__main__":
    unittest.main()
