import os
import platform
import subprocess
import time
import json
from datetime import datetime
from typing import Dict, Any, List

from .database import DatabaseManager
from .events import EventBus
from .resources import ResourceManager
from .models import Experiment, ExperimentState

class ExperimentManager:
    """Manages the full lifecycle of a research experiment."""

    def __init__(self, db: DatabaseManager, event_bus: EventBus, resource_mgr: ResourceManager):
        self.db = db
        self.event_bus = event_bus
        self.resources = resource_mgr

    def create_experiment(self, project_id: str, title: str, researcher: str, 
                          config: Dict[str, Any], variables: Dict[str, Any]) -> str:
        """Create a new experiment draft."""
        with self.db.session_scope() as session:
            exp = Experiment(
                project_id=project_id,
                title=title,
                variables=variables,
                configuration=config,
                state=ExperimentState.DRAFT
            )
            session.add(exp)
            session.flush() # flush to get the UUID
            exp_id = exp.id
            
        self.event_bus.publish(
            source="ExperimentManager",
            event_type="experiment.created",
            experiment_id=exp_id,
            payload={"title": title, "project_id": project_id}
        )
        return exp_id

    def transition_state(self, experiment_id: str, new_state: ExperimentState) -> bool:
        """Transition experiment to a new state and log the event."""
        with self.db.session_scope() as session:
            exp = session.query(Experiment).filter_by(id=experiment_id).first()
            if not exp:
                return False
                
            old_state = exp.state
            exp.state = new_state
            
            if new_state == ExperimentState.RUNNING and not exp.start_time:
                exp.start_time = datetime.utcnow()
            elif new_state in (ExperimentState.COMPLETED, ExperimentState.FAILED, ExperimentState.ARCHIVED):
                if not exp.end_time:
                    exp.end_time = datetime.utcnow()
                # Auto-release hardware
                self.resources.release_all_for_experiment(experiment_id)
                # Generate reproducibility manifest if finishing
                if new_state == ExperimentState.COMPLETED and not exp.reproducibility_manifest:
                    exp.reproducibility_manifest = self.generate_manifest(exp)
                    
        self.event_bus.publish(
            source="ExperimentManager",
            event_type="experiment.state_changed",
            experiment_id=experiment_id,
            payload={"old_state": old_state.name, "new_state": new_state.name}
        )
        return True

    def generate_manifest(self, experiment: Experiment) -> Dict[str, Any]:
        """Generates a complete PhD-level reproducibility manifest."""
        manifest = {
            "timestamp": datetime.utcnow().isoformat(),
            "experiment_id": experiment.id,
            "project_id": experiment.project_id,
            "environment": {
                "os": platform.platform(),
                "python_version": platform.python_version(),
                "node": platform.node(),
            },
            "configuration": experiment.configuration,
            "variables": experiment.variables,
            "git": self._get_git_info(),
            "dependencies": self._get_pip_freeze()
        }
        return manifest
        
    def _get_git_info(self) -> Dict[str, str]:
        info = {"commit": "unknown", "branch": "unknown", "dirty": False}
        try:
            rc = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=2)
            if rc.returncode == 0:
                info["commit"] = rc.stdout.strip()
                
            rc_branch = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True, text=True, timeout=2)
            if rc_branch.returncode == 0:
                info["branch"] = rc_branch.stdout.strip()
                
            rc_status = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, timeout=2)
            info["dirty"] = bool(rc_status.stdout.strip())
        except Exception:
            pass
        return info

    def _get_pip_freeze(self) -> List[str]:
        try:
            rc = subprocess.run(["pip", "freeze"], capture_output=True, text=True, timeout=5)
            if rc.returncode == 0:
                return rc.stdout.strip().split("\n")
        except Exception:
            pass
        return []
