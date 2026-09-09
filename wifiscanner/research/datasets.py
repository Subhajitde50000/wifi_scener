import hashlib
from typing import Dict, Any, List, Optional
from .database import DatabaseManager
from .models import Dataset, GroundTruth

class DatasetManager:
    """Manages the creation, versioning, and labeling of research datasets."""
    
    def __init__(self, db: DatabaseManager):
        self.db = db

    def create_dataset(self, name: str, source_type: str, version: str = "1.0.0", 
                       experiment_id: Optional[str] = None, meta: Dict[str, Any] = None) -> str:
        """Create a new dataset registry entry."""
        with self.db.session_scope() as session:
            ds = Dataset(
                name=name,
                source_type=source_type,
                version=version,
                experiment_id=experiment_id,
                metadata_info=meta or {}
            )
            session.add(ds)
            session.flush()
            return ds.id

    def update_checksum(self, dataset_id: str, file_path: str):
        """Compute and store a SHA-256 checksum for a static dataset artifact."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        chk = hasher.hexdigest()
        with self.db.session_scope() as session:
            ds = session.query(Dataset).filter_by(id=dataset_id).first()
            if ds:
                ds.checksum = chk
        return chk

    def add_ground_truth(self, dataset_id: str, observation_ref: str, label: str, 
                         confidence: float = 1.0, provenance: Dict[str, Any] = None) -> str:
        """Add a ground truth label to a specific observation in a dataset."""
        with self.db.session_scope() as session:
            gt = GroundTruth(
                dataset_id=dataset_id,
                observation_ref=observation_ref,
                label=label,
                confidence=confidence,
                provenance=provenance or {}
            )
            session.add(gt)
            session.flush()
            return gt.id

    def get_labels(self, dataset_id: str) -> List[Dict[str, Any]]:
        """Retrieve all ground truth labels for a dataset."""
        with self.db.session_scope() as session:
            labels = session.query(GroundTruth).filter_by(dataset_id=dataset_id).all()
            return [
                {
                    "ref": l.observation_ref,
                    "label": l.label,
                    "confidence": l.confidence,
                    "provenance": l.provenance
                } for l in labels
            ]
