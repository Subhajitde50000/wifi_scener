import unittest
import os
import tempfile

from wifiscanner.research import (
    DatabaseManager, DatasetManager, ProjectManager, Statistics, 
    ExperimentDesign, IndependentVariable, DependentVariable, ControlledVariable
)

class TestResearchPlatformPhase2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = f"sqlite:///{self.tmp.name}"
        self.db = DatabaseManager(self.db_path)
        self.db.initialize_schema()
        
        self.dataset_mgr = DatasetManager(self.db)
        self.project_mgr = ProjectManager(self.db)

    def tearDown(self):
        os.unlink(self.tmp.name)

    def test_project_management(self):
        pid = self.project_mgr.create_project("Anomaly Detection", "Test Desc", "Dr. A")
        self.assertIsNotNone(pid)
        
        projs = self.project_mgr.list_projects()
        self.assertEqual(len(projs), 1)
        self.assertEqual(projs[0]["name"], "Anomaly Detection")

    def test_experiment_designer(self):
        design = ExperimentDesign(hypothesis="Channel width affects latency")
        design.add_iv(IndependentVariable("width", "Channel Width", int, [20, 40, 80]))
        design.add_dv(DependentVariable("latency", "Packet Latency", float, ["mean", "std_dev"]))
        design.add_cv(ControlledVariable("tx_power", "Transmit Power dBm", int, 20))
        design.repetitions = 2
        design.randomization_seed = 42
        
        matrix = design.generate_matrix()
        # 3 levels * 2 reps = 6 trials
        self.assertEqual(len(matrix), 6)
        
        # Check trial structure
        t = matrix[0]
        self.assertIn("width", t)
        self.assertEqual(t["tx_power"], 20)
        self.assertIn("_repetition", t)
        self.assertIn("_group_id", t)

    def test_dataset_and_ground_truth(self):
        ds_id = self.dataset_mgr.create_dataset(
            name="MAC Randomization Trace",
            source_type="SYNTHETIC",
            version="1.0.0",
            meta={"duration": 3600}
        )
        self.assertIsNotNone(ds_id)
        
        gt1 = self.dataset_mgr.add_ground_truth(ds_id, "evt-100", "True Positive", 0.99, {"detector": "A"})
        gt2 = self.dataset_mgr.add_ground_truth(ds_id, "evt-101", "False Positive", 1.0)
        
        self.assertIsNotNone(gt1)
        
        labels = self.dataset_mgr.get_labels(ds_id)
        self.assertEqual(len(labels), 2)
        
        l1 = [l for l in labels if l["ref"] == "evt-100"][0]
        self.assertEqual(l1["label"], "True Positive")
        self.assertEqual(l1["provenance"], {"detector": "A"})

    def test_statistics(self):
        data = [10.0, 12.0, 15.0, 10.0, 11.0]
        
        self.assertEqual(Statistics.mean(data), 11.6)
        self.assertEqual(Statistics.median(data), 11.0)
        
        var = Statistics.variance(data, sample=True)
        self.assertAlmostEqual(var, 4.3, places=2)
        
        std = Statistics.std_dev(data, sample=True)
        self.assertAlmostEqual(std, 2.07, places=2)
        
        summary = Statistics.summary(data)
        self.assertEqual(summary["count"], 5)
        self.assertEqual(summary["min"], 10.0)
        self.assertEqual(summary["max"], 15.0)

if __name__ == "__main__":
    unittest.main()
