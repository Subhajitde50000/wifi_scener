import os
import json
from typing import Dict, Any, List

from .database import DatabaseManager
from .events import EventBus
from .experiment import ExperimentManager
from .resources import ResourceManager
from .datasets import DatasetManager
from .models import ExperimentState

class WPALabResearchAdapter:
    """Adapts the WPA Cryptography Offline Lab into the Research Platform Dataset layer."""
    
    def __init__(self, db: DatabaseManager, exp_mgr: ExperimentManager, dataset_mgr: DatasetManager):
        self.db = db
        self.exp_mgr = exp_mgr
        self.dataset_mgr = dataset_mgr

    def setup_wpa_experiment(self, project_id: str, pcap_path: str, parameters: Dict[str, Any] = None) -> str:
        """Configures a decryption benchmarking experiment."""
        config = {
            "pcap_target": pcap_path,
            "target": "WPA Cryptography Benchmark",
            "parameters": parameters or {}
        }
        
        variables = {
            "independent": [
                {"name": "decryption_key", "levels": ["correct", "incorrect", "missing"]}
            ],
            "dependent": [
                {"name": "frames_decrypted"},
                {"name": "mic_failures"},
                {"name": "time_to_decrypt"}
            ]
        }
        
        exp_id = self.exp_mgr.create_experiment(
            project_id=project_id,
            title="WPA Protocol Offline Analysis",
            researcher="Cryptography Integration",
            config=config,
            variables=variables
        )
        return exp_id

    def import_fixture_as_dataset(self, pcap_path: str, meta: Dict[str, Any], exp_id: str = None) -> str:
        """Registers a generated fixture (PCAP) as a traceable Research Dataset."""
        ds_id = self.dataset_mgr.create_dataset(
            name=f"WPA Fixture: {meta.get('ssid', 'Unknown')}",
            source_type="SYNTHETIC-PCAP",
            version="1.0.0",
            experiment_id=exp_id,
            meta=meta
        )
        self.dataset_mgr.update_checksum(ds_id, pcap_path)
        return ds_id

class TrackLabResearchAdapter:
    """Adapts the Tracking / MAC Randomization lab into the Research Dataset & Statistical ML Layer."""
    
    def __init__(self, db: DatabaseManager, exp_mgr: ExperimentManager, dataset_mgr: DatasetManager):
        self.db = db
        self.exp_mgr = exp_mgr
        self.dataset_mgr = dataset_mgr

    def import_tracking_dataset(self, dataset_dir: str, meta: Dict[str, Any], exp_id: str = None) -> str:
        """Registers a Tracking synthetic matrix as a Research Dataset."""
        ds_id = self.dataset_mgr.create_dataset(
            name=f"Device Tracking Trace (Seed {meta.get('seed', 'N/A')})",
            source_type="SYNTHETIC-TRACE",
            version="1.0.0",
            experiment_id=exp_id,
            meta=meta
        )
        # Import actual truth labels as GT for benchmark framework
        truth_file = os.path.join(dataset_dir, "ground-truth.csv")
        if os.path.exists(truth_file):
            import csv
            with open(truth_file, "r") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # 'mac' represents the primary target
                    self.dataset_mgr.add_ground_truth(
                        ds_id,
                        observation_ref=row.get("mac", ""),
                        label=row.get("identity", "Unknown"),
                        confidence=1.0,
                        provenance={"source": "ground-truth.csv", "type": row.get("type", "")}
                    )
        return ds_id
