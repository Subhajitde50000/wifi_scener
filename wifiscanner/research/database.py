import os
import contextlib
from typing import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session

from .models import Base

class DatabaseManager:
    """Manages the research platform's underlying SQLAlchemy engine and sessions."""
    
    def __init__(self, db_url: str = "sqlite:///research.sqlite"):
        # For sqlite, enforce foreign keys and enable WAL mode for high concurrency
        connect_args = {}
        if db_url.startswith("sqlite"):
            connect_args = {"check_same_thread": False}
            
        self.engine = create_engine(db_url, connect_args=connect_args)
        
        if db_url.startswith("sqlite"):
            with self.engine.connect() as conn:
                conn.exec_driver_sql("PRAGMA journal_mode=WAL")
                conn.exec_driver_sql("PRAGMA foreign_keys=ON")
                
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        
    def initialize_schema(self):
        """Creates all tables."""
        Base.metadata.create_all(bind=self.engine)

    @contextlib.contextmanager
    def session_scope(self) -> Generator[Session, None, None]:
        """Provide a transactional scope around a series of operations."""
        session = self.SessionLocal()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
