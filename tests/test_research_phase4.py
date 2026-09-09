import unittest
import time
from wifiscanner.research import BenchmarkFramework, DatasetManager
from wifiscanner.research.features import WatchdogDetectorAdapter

class MockScapyFrame:
    def __init__(self, type, subtype, addr2, addr3, has_eapol=False, is_beacon=False, ssids=None):
        self.type = type
        self.subtype = subtype
        self.addr1 = "CC"
        self.addr2 = addr2
        self.addr3 = addr3
        self._has_eapol = has_eapol
        self._is_beacon = is_beacon
        self._ssids = ssids or []
        self.time = time.time()
        
    def haslayer(self, layer):
        if layer.__name__ == "Dot11": return True
        if layer.__name__ == "Dot11Beacon": return self._is_beacon
        if layer.__name__ == "EAPOL": return self._has_eapol
        return False

    def __getitem__(self, layer):
        if layer.__name__ == "Dot11":
            class Dot11: pass
            d = Dot11()
            d.type = self.type
            d.subtype = self.subtype
            d.addr1 = self.addr1
            d.addr2 = self.addr2
            d.addr3 = self.addr3
            return d
        raise KeyError()


class TestResearchPhase4(unittest.TestCase):
    def test_watchdog_as_research_detector(self):
        # We simulate a deauth flood.
        
        # 1. Ground truth
        labels = [
            {"ref": f"evt-{i}", "label": "Attack" if i > 3 else "Negative"}
            for i in range(1, 8)
        ]
        
        bench = BenchmarkFramework(labels)
        
        # 2. Event stream
        events = []
        for i in range(1, 8):
            # 7 Deauth frames (type 0, subtype 12) sent rapidly
            # Watchdog defaults to flood_n = 5.
            # At i=5, it hits threshold (5 >= 5) and creates an alert.
            # We map Attack to i>3 (meaning i=4,5,6,7 are attacks)
            # Actually, let's just make it a clean threshold hit test
            f = MockScapyFrame(type=0, subtype=12, addr2="AA", addr3="BB")
            events.append({"id": f"evt-{i}", "frame": f})
            
        # 3. Detector under test
        detector = WatchdogDetectorAdapter({"flood_frames": 5})
        
        metrics = bench.evaluate_detector(detector, events)
        
        self.assertGreater(metrics["total_processed"], 0)
        # We sent 7 frames. Frame 1-4: no alert. Frame 5, 6, 7: alert.
        self.assertGreater(metrics["detector_summary"]["total_alerts"], 0)

if __name__ == "__main__":
    unittest.main()
