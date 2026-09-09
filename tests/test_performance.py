import unittest
import time
import os
import tempfile
import threading

from wifiscanner.research import DatabaseManager, EventBus, ExperimentManager, ResourceManager, ProjectManager, ExperimentState

class TestPerformanceAndRecovery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = f"sqlite:///{self.tmp.name}"
        self.db = DatabaseManager(self.db_path)
        self.db.initialize_schema()
        self.event_bus = EventBus(self.db)
        self.event_bus.start()
        self.resource_mgr = ResourceManager(self.db)
        self.exp_mgr = ExperimentManager(self.db, self.event_bus, self.resource_mgr)
        self.pm = ProjectManager(self.db)
        self.project_id = self.pm.create_project("Perf and Recovery")

    def tearDown(self):
        self.event_bus.stop()
        os.unlink(self.tmp.name)

    def test_event_bus_throughput(self):
        """Test how fast the event bus and DB batching can ingest events."""
        exp_id = self.exp_mgr.create_experiment(self.project_id, "Throughput Test", "Automated", {}, {})
        
        start = time.time()
        num_events = 1000
        
        # Publish events rapidly
        for i in range(num_events):
            self.event_bus.publish(
                source="PerfTest",
                event_type="test.event",
                payload={"index": i, "data": "A" * 128},
                experiment_id=exp_id
            )
            
        # Give the worker thread a moment to flush batch (max 1 second delay + processing time)
        time.sleep(1.5)
        
        end = time.time()
        
        with self.db.session_scope() as session:
            from wifiscanner.research import EventLog
            count = session.query(EventLog).filter_by(experiment_id=exp_id, event_type="test.event").count()
            
        self.assertEqual(count, num_events, f"Expected {num_events} events but got {count}")
        duration = end - start
        
        print(f"\\n[Performance] Ingested {num_events} events in {duration:.2f} seconds ({num_events/duration:.2f} eps)")
        
    def test_experiment_failure_recovery(self):
        """Test that if an experiment fails unexpectedly, hardware resources are released."""
        from wifiscanner.research import Resource, ResourceState
        
        with self.db.session_scope() as session:
            r = Resource(id="wlan_test", resource_type="interface", capabilities=["monitor_mode"])
            session.add(r)
            
        exp_id = self.exp_mgr.create_experiment(self.project_id, "Failure Test", "Automated", {}, {})
        
        # Allocate resource
        success = self.resource_mgr.allocate("wlan_test", exp_id, ["monitor_mode"])
        self.assertTrue(success)
        
        self.exp_mgr.transition_state(exp_id, ExperimentState.RUNNING)
        
        with self.db.session_scope() as session:
            r = session.query(Resource).filter_by(id="wlan_test").first()
            self.assertEqual(r.state, ResourceState.ALLOCATED)
            
        # Simulate a crash or failure transition
        self.exp_mgr.transition_state(exp_id, ExperimentState.FAILED)
        
        # Verify resource is released and available again
        with self.db.session_scope() as session:
            r = session.query(Resource).filter_by(id="wlan_test").first()
            self.assertEqual(r.state, ResourceState.AVAILABLE)
            self.assertIsNone(r.current_experiment_id)

    def test_concurrent_experiments(self):
        """Test running multiple experiments simultaneously to check isolation."""
        def run_exp(name):
            exp_id = self.exp_mgr.create_experiment(self.project_id, name, "Automated", {}, {})
            self.exp_mgr.transition_state(exp_id, ExperimentState.RUNNING)
            for i in range(50):
                self.event_bus.publish("ConcurrentTest", "event", {"val": i}, experiment_id=exp_id)
            self.exp_mgr.transition_state(exp_id, ExperimentState.COMPLETED)
            
        threads = [threading.Thread(target=run_exp, args=(f"Exp-{i}",)) for i in range(5)]
        for t in threads: t.start()
        for t in threads: t.join()
        
        time.sleep(1.0)
        
        with self.db.session_scope() as session:
            from wifiscanner.research import Experiment, EventLog
            completed = session.query(Experiment).filter_by(state=ExperimentState.COMPLETED).count()
            self.assertEqual(completed, 5)
            
            events = session.query(EventLog).count()
            # 5 * 50 + 5 creates + 10 transitions = ~275 events minimum
            self.assertGreaterEqual(events, 250)

if __name__ == "__main__":
    unittest.main()
