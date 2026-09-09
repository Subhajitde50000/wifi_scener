import enum
import json
import uuid
from datetime import datetime
from typing import Any, Dict

from sqlalchemy import Column, String, Integer, Float, Boolean, ForeignKey, DateTime, Enum, JSON, Text
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()

def generate_uuid() -> str:
    return str(uuid.uuid4())

class ExperimentState(enum.Enum):
    DRAFT = "DRAFT"
    DESIGNED = "DESIGNED"
    AUTHORIZED = "AUTHORIZED"
    ALLOCATED = "ALLOCATED"
    READY = "READY"
    RUNNING = "RUNNING"
    PAUSED = "PAUSED"
    STOPPING = "STOPPING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    RESETTING = "RESETTING"
    RESET = "RESET"
    ARCHIVED = "ARCHIVED"

class ResourceState(enum.Enum):
    AVAILABLE = "AVAILABLE"
    ALLOCATED = "ALLOCATED"
    UNHEALTHY = "UNHEALTHY"
    OFFLINE = "OFFLINE"

class Project(Base):
    __tablename__ = "research_projects"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    researcher = Column(String(255), nullable=True)
    supervisor = Column(String(255), nullable=True)
    hypothesis = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    experiments = relationship("Experiment", back_populates="project", cascade="all, delete-orphan")

class Experiment(Base):
    __tablename__ = "research_experiments"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    project_id = Column(String(36), ForeignKey("research_projects.id"), nullable=False)
    title = Column(String(255), nullable=False)
    research_question = Column(Text, nullable=True)
    state = Column(Enum(ExperimentState), default=ExperimentState.DRAFT, nullable=False)
    
    # Designer parameters
    variables = Column(JSON, default=dict, nullable=False)  # indep, dep, controlled
    configuration = Column(JSON, default=dict, nullable=False)
    
    # Execution tracking
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    
    # Reproducibility
    reproducibility_manifest = Column(JSON, nullable=True)
    
    project = relationship("Project", back_populates="experiments")
    artifacts = relationship("Artifact", back_populates="experiment", cascade="all, delete-orphan")
    events = relationship("EventLog", back_populates="experiment", cascade="all, delete-orphan")
    datasets = relationship("Dataset", back_populates="experiment")

class Dataset(Base):
    __tablename__ = "research_datasets"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    experiment_id = Column(String(36), ForeignKey("research_experiments.id"), nullable=True)
    name = Column(String(255), nullable=False)
    version = Column(String(50), default="1.0.0")
    source_type = Column(String(50), nullable=False) # e.g., LIVE, PCAP, SYNTHETIC
    metadata_info = Column(JSON, default=dict)
    checksum = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    experiment = relationship("Experiment", back_populates="datasets")
    labels = relationship("GroundTruth", back_populates="dataset", cascade="all, delete-orphan")

class GroundTruth(Base):
    __tablename__ = "research_ground_truth"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    dataset_id = Column(String(36), ForeignKey("research_datasets.id"), nullable=False)
    observation_ref = Column(String(128), nullable=False) # ID of event, packet hash, etc.
    label = Column(String(128), nullable=False)
    confidence = Column(Float, default=1.0)
    provenance = Column(JSON, default=dict)
    
    dataset = relationship("Dataset", back_populates="labels")

class MLModel(Base):
    __tablename__ = "research_ml_models"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    name = Column(String(255), nullable=False)
    project_id = Column(String(36), ForeignKey("research_projects.id"), nullable=True)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    versions = relationship("MLModelVersion", back_populates="model", cascade="all, delete-orphan")

class MLModelVersion(Base):
    __tablename__ = "research_ml_model_versions"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    model_id = Column(String(36), ForeignKey("research_ml_models.id"), nullable=False)
    version_tag = Column(String(50), nullable=False)
    hyperparameters = Column(JSON, default=dict)
    metrics = Column(JSON, default=dict)
    artifact_path = Column(String(1024), nullable=True)
    dataset_id = Column(String(36), ForeignKey("research_datasets.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    model = relationship("MLModel", back_populates="versions")

class Artifact(Base):
    __tablename__ = "research_artifacts"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    experiment_id = Column(String(36), ForeignKey("research_experiments.id"), nullable=False)
    artifact_type = Column(String(50), nullable=False)  # pcap, model, report, dataset
    path = Column(String(1024), nullable=False)
    checksum_sha256 = Column(String(64), nullable=True)
    provenance = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    experiment = relationship("Experiment", back_populates="artifacts")

class EventLog(Base):
    __tablename__ = "research_events"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    experiment_id = Column(String(36), ForeignKey("research_experiments.id"), nullable=True)
    timestamp = Column(Float, nullable=False)
    source = Column(String(128), nullable=False)
    event_type = Column(String(128), nullable=False)
    severity = Column(String(20), default="INFO")
    correlation_id = Column(String(36), nullable=True)
    payload = Column(JSON, default=dict)
    
    experiment = relationship("Experiment", back_populates="events")

class Resource(Base):
    __tablename__ = "research_resources"
    
    id = Column(String(128), primary_key=True)  # e.g. "wlan0", "dataset-xyz"
    resource_type = Column(String(50), nullable=False) # "interface", "ap", "dataset"
    capabilities = Column(JSON, default=list) # e.g. ["monitor_mode", "injection"]
    state = Column(Enum(ResourceState), default=ResourceState.AVAILABLE)
    current_experiment_id = Column(String(36), ForeignKey("research_experiments.id"), nullable=True)
    last_heartbeat = Column(Float, nullable=True)
