import random
from typing import List, Dict, Any, Tuple

from .database import DatabaseManager
from .models import MLModel, MLModelVersion

class MLResearchPipeline:
    """Manages ML model lifecycle, tracking parameters, and repeatable data splitting."""
    
    def __init__(self, db: DatabaseManager):
        self.db = db

    def train_test_split(self, data: List[Any], labels: List[Any], 
                         test_ratio: float = 0.2, seed: int = 42) -> Tuple[List, List, List, List]:
        """
        Creates a reproducible train/test split.
        Returns: (train_x, test_x, train_y, test_y)
        """
        if len(data) != len(labels):
            raise ValueError("Data and labels must have the same length")
            
        combined = list(zip(data, labels))
        rng = random.Random(seed)
        rng.shuffle(combined)
        
        split_idx = int(len(combined) * (1 - test_ratio))
        train = combined[:split_idx]
        test = combined[split_idx:]
        
        if not train and not test:
            return [], [], [], []
            
        train_x, train_y = zip(*train) if train else ([], [])
        test_x, test_y = zip(*test) if test else ([], [])
        
        return list(train_x), list(test_x), list(train_y), list(test_y)

    def register_model(self, name: str, project_id: str = None, description: str = "") -> str:
        """Register a new ML model in the research database."""
        with self.db.session_scope() as session:
            m = MLModel(name=name, project_id=project_id, description=description)
            session.add(m)
            session.flush()
            return m.id

    def save_version(self, model_id: str, version: str, 
                     params: Dict[str, Any], metrics: Dict[str, Any], 
                     artifact: str = "", dataset_id: str = None) -> str:
        """Record a trained model version with hyperparams and test metrics."""
        with self.db.session_scope() as session:
            mv = MLModelVersion(
                model_id=model_id, 
                version_tag=version, 
                hyperparameters=params, 
                metrics=metrics, 
                artifact_path=artifact, 
                dataset_id=dataset_id
            )
            session.add(mv)
            session.flush()
            return mv.id
            
    def get_versions(self, model_id: str) -> List[Dict[str, Any]]:
        """Retrieve all tracked versions and metrics for a specific model."""
        with self.db.session_scope() as session:
            versions = session.query(MLModelVersion).filter_by(model_id=model_id).all()
            return [
                {
                    "version_tag": v.version_tag,
                    "hyperparameters": v.hyperparameters,
                    "metrics": v.metrics,
                    "artifact_path": v.artifact_path,
                    "dataset_id": v.dataset_id
                } for v in versions
            ]
