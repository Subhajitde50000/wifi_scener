import os
from typing import Dict, Any, List

from .models import ExperimentState
from .database import DatabaseManager
from .events import EventBus
from .experiment import ExperimentManager
from .resources import ResourceManager
from .features import WatchdogDetectorAdapter

class IDSResearchAdapter:
    """Adapts the CLI-based IDS functionality into a true Research Platform Experiment."""
    
    def __init__(self, db: DatabaseManager, event_bus: EventBus, resource_mgr: ResourceManager, exp_mgr: ExperimentManager):
        self.db = db
        self.event_bus = event_bus
        self.resource_mgr = resource_mgr
        self.exp_mgr = exp_mgr
        
    def setup_ids_experiment(self, project_id: str, interface: str, window: float, flood: int, sensitivity: str) -> str:
        """Configures a new experiment specifically for running the IDS detector."""
        config = {
            "window_s": window,
            "flood_frames": flood,
            "sensitivity": sensitivity,
            "interface": interface,
            "target": "IDS Research Validation"
        }
        
        variables = {
            "independent": [
                {"name": "sensitivity", "levels": ["low", "medium", "high"]}
            ],
            "dependent": [
                {"name": "true_positive_rate"},
                {"name": "latency"}
            ]
        }
        
        exp_id = self.exp_mgr.create_experiment(
            project_id=project_id,
            title="Wireless IDS Research Capture",
            researcher="Automated Integration",
            config=config,
            variables=variables
        )
        return exp_id
        
    def start_live_ids(self, exp_id: str):
        """Starts a live packet capture tied to the experiment ID."""
        with self.db.session_scope() as session:
            from .models import Experiment
            exp = session.query(Experiment).filter_by(id=exp_id).first()
            if not exp:
                raise ValueError("Experiment not found")
            iface = exp.configuration.get("interface")
            
        # Allocate hardware
        if iface and iface != "pcap":
            if not self.resource_mgr.allocate(iface, exp_id, required_caps=["monitor_mode"]):
                raise RuntimeError(f"Could not allocate resource {iface} for IDS")
                
        self.exp_mgr.transition_state(exp_id, ExperimentState.RUNNING)
        self.event_bus.publish("IDSAdapter", "experiment.started", {"iface": iface}, experiment_id=exp_id)
        
        # At this point, the main CLI would loop the sniffer, publishing 'frame.captured' events to the EventBus.
        # The WatchdogDetectorAdapter would be subscribed to process them.
        
    def stop_ids(self, exp_id: str):
        """Stops the IDS and transitions the experiment cleanly."""
        self.exp_mgr.transition_state(exp_id, ExperimentState.COMPLETED)
        # Resource manager auto-releases hardware on COMPLETED transition.
