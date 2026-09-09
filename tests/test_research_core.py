import unittest
import os
import tempfile
import time

from wifiscanner.research import (
    DatabaseManager, EventBus, ResourceManager, ExperimentManager,
    Project, Experiment, ExperimentState, ResourceState, Resource, EventLog
)

class TestResearchPlatformCore(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.db_path = f"sqlite:///{self.tmp.name}"
        self.db = DatabaseManager(self.db_path)
        self.db.initialize_schema()
        
        self.event_bus = EventBus(self.db)
        self.event_bus.start()
        
        self.resource_mgr = ResourceManager(self.db)
        self.exp_mgr = ExperimentManager(self.db, self.event_bus, self.resource_mgr)

    def tearDown(self):
        self.event_bus.stop()
        os.unlink(self.tmp.name)

    def test_database_initialization(self):
        with self.db.session_scope() as session:
            p = Project(name="Test Project", researcher="Dr. Smith")
            session.add(p)
            session.flush()
            self.assertIsNotNone(p.id)
            self.assertEqual(p.name, "Test Project")

    def test_experiment_lifecycle_and_events(self):
        # Create Project
        with self.db.session_scope() as session:
            p = Project(name="Test Project")
            session.add(p)
            session.flush()
            pid = p.id

        # Setup an event catcher
        captured_events = []
        def catch_all(event):
            captured_events.append(event)
            
        self.event_bus.subscribe("*", catch_all)

        # Create Experiment
        exp_id = self.exp_mgr.create_experiment(
            project_id=pid,
            title="Protocol Fuzzing",
            researcher="Dr. Smith",
            config={"channel": 6, "target": "AP-1"},
            variables={"independent": ["packet_rate"]}
        )
        
        self.assertIsNotNone(exp_id)

        # Transition state
        self.exp_mgr.transition_state(exp_id, ExperimentState.RUNNING)
        self.exp_mgr.transition_state(exp_id, ExperimentState.COMPLETED)
        
        # Wait for events to flush
        time.sleep(0.5)

        with self.db.session_scope() as session:
            exp = session.query(Experiment).filter_by(id=exp_id).first()
            self.assertEqual(exp.state, ExperimentState.COMPLETED)
            self.assertIsNotNone(exp.reproducibility_manifest)
            self.assertIn("git", exp.reproducibility_manifest)
            self.assertIn("environment", exp.reproducibility_manifest)

        # Check in-memory event bus
        self.assertGreaterEqual(len(captured_events), 3)  # create, to RUNNING, to COMPLETED
        
        # Wait a bit longer for DB flush threshold (1.0s)
        time.sleep(1.0)
        
        # Check event logs in DB
        with self.db.session_scope() as session:
            db_events = session.query(EventLog).filter_by(experiment_id=exp_id).all()
            self.assertGreaterEqual(len(db_events), 3)
            self.assertTrue(any(e.event_type == "experiment.created" for e in db_events))

    def test_resource_allocation(self):
        # Create an experiment to hold the foreign key
        with self.db.session_scope() as session:
            p = Project(name="Project X")
            session.add(p)
            session.flush()
            exp = Experiment(id="exp-123", project_id=p.id, title="Test", state=ExperimentState.DRAFT)
            session.add(exp)

        # Register fake resource
        with self.db.session_scope() as session:
            r = Resource(id="wlan1", resource_type="interface", capabilities=["monitor_mode"])
            session.add(r)
            
        # Allocate
        success = self.resource_mgr.allocate("wlan1", "exp-123", required_caps=["monitor_mode"])
        self.assertTrue(success)
        
        # Double allocate fails
        success2 = self.resource_mgr.allocate("wlan1", "exp-456")
        self.assertFalse(success2)
        
        # Check state
        with self.db.session_scope() as session:
            r = session.query(Resource).filter_by(id="wlan1").first()
            self.assertEqual(r.state, ResourceState.ALLOCATED)
            self.assertEqual(r.current_experiment_id, "exp-123")
            
        # Release
        self.resource_mgr.release("wlan1", "exp-123")
        with self.db.session_scope() as session:
            r = session.query(Resource).filter_by(id="wlan1").first()
            self.assertEqual(r.state, ResourceState.AVAILABLE)
            self.assertIsNone(r.current_experiment_id)

if __name__ == "__main__":
    unittest.main()
