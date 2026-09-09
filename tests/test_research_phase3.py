import unittest
import os
import tempfile

from wifiscanner.research import (
    DatabaseManager, MLResearchPipeline, PluginManager, 
    DetectorInterface, AnalyzerSDK, DatasetProcessorSDK
)

# Dummy plugin classes for testing module loading
class MyCustomDetector(DetectorInterface):
    def process_event(self, event): return None

class MyCustomAnalyzer(AnalyzerSDK):
    def analyze(self, dataset_id, events): return {"status": "ok"}

class MyCustomProcessor(DatasetProcessorSDK):
    def process(self, raw_data): return raw_data

class TestResearchPlatformPhase3(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = f"sqlite:///{self.tmp.name}"
        self.db = DatabaseManager(self.db_path)
        self.db.initialize_schema()
        self.ml_pipeline = MLResearchPipeline(self.db)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_ml_pipeline_split(self):
        data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        labels = [0, 0, 0, 0, 0, 1, 1, 1, 1, 1]
        
        tx, tex, ty, tey = self.ml_pipeline.train_test_split(data, labels, test_ratio=0.2, seed=42)
        
        self.assertEqual(len(tx), 8)
        self.assertEqual(len(tex), 2)
        self.assertEqual(len(ty), 8)
        self.assertEqual(len(tey), 2)
        
        # Test determinism
        tx2, tex2, ty2, tey2 = self.ml_pipeline.train_test_split(data, labels, test_ratio=0.2, seed=42)
        self.assertEqual(tx, tx2)

    def test_ml_model_tracking(self):
        model_id = self.ml_pipeline.register_model(
            name="RF-Anomaly-RandomForest", 
            description="RF classifier for beacon mutations"
        )
        self.assertIsNotNone(model_id)
        
        mv_id = self.ml_pipeline.save_version(
            model_id=model_id,
            version="v1.0.0",
            params={"n_estimators": 100, "max_depth": 5},
            metrics={"accuracy": 0.95, "f1_score": 0.92}
        )
        self.assertIsNotNone(mv_id)
        
        versions = self.ml_pipeline.get_versions(model_id)
        self.assertEqual(len(versions), 1)
        self.assertEqual(versions[0]["version_tag"], "v1.0.0")
        self.assertEqual(versions[0]["hyperparameters"]["n_estimators"], 100)
        self.assertEqual(versions[0]["metrics"]["accuracy"], 0.95)

    def test_plugin_manager(self):
        # We will trick the plugin manager into loading this very test file
        pm = PluginManager()
        counts = pm.load_from_module("tests.test_research_phase3")
        
        self.assertEqual(counts["detectors"], 1)
        self.assertEqual(counts["analyzers"], 1)
        self.assertEqual(counts["processors"], 1)
        
        detector = pm.get_detector("MyCustomDetector")
        self.assertEqual(detector.__class__.__name__, "MyCustomDetector")
        
        analyzer = pm.get_analyzer("MyCustomAnalyzer")
        self.assertEqual(analyzer.__class__.__name__, "MyCustomAnalyzer")
        self.assertEqual(analyzer.analyze("ds1", []), {"status": "ok"})
        
        processor = pm.get_processor("MyCustomProcessor")
        self.assertEqual(processor.__class__.__name__, "MyCustomProcessor")
        self.assertEqual(processor.process([1, 2]), [1, 2])

if __name__ == "__main__":
    unittest.main()
