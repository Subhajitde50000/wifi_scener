import time
from typing import Dict, Any, List, Optional
from .database import DatabaseManager
from .models import Project, Experiment

class ProjectManager:
    """Manages research projects and enables cross-experiment comparisons."""
    
    def __init__(self, db: DatabaseManager):
        self.db = db
        
    def create_project(self, name: str, description: str = "", 
                       researcher: str = "", hypothesis: str = "") -> str:
        with self.db.session_scope() as session:
            p = Project(
                name=name,
                description=description,
                researcher=researcher,
                hypothesis=hypothesis
            )
            session.add(p)
            session.flush()
            return p.id

    def list_projects(self) -> List[Dict[str, Any]]:
        with self.db.session_scope() as session:
            projects = session.query(Project).all()
            return [{"id": p.id, "name": p.name, "researcher": p.researcher} for p in projects]

    def get_experiments(self, project_id: str) -> List[Dict[str, Any]]:
        with self.db.session_scope() as session:
            experiments = session.query(Experiment).filter_by(project_id=project_id).all()
            return [{
                "id": e.id,
                "title": e.title,
                "state": e.state.name,
                "start_time": e.start_time.timestamp() if e.start_time else None
            } for e in experiments]
