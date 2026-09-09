import os
import subprocess
import logging
from typing import List, Dict, Any, Optional

from .database import DatabaseManager
from .models import Resource, ResourceState

logger = logging.getLogger(__name__)

class HardwareDiscovery:
    @staticmethod
    def discover_linux_wifi_interfaces() -> List[Dict[str, Any]]:
        interfaces = []
        if not os.path.exists("/sys/class/net"):
            return interfaces
            
        for iface in os.listdir("/sys/class/net"):
            phy80211 = os.path.join("/sys/class/net", iface, "phy80211")
            wireless = os.path.join("/sys/class/net", iface, "wireless")
            if os.path.exists(phy80211) or os.path.exists(wireless):
                caps = ["packet_capture", "wifi"]
                # Try to see if it supports monitor mode using iw
                try:
                    rc = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, timeout=2)
                    if "type monitor" in rc.stdout:
                        caps.append("monitor_mode")
                        caps.append("radiotap")
                except Exception:
                    pass
                    
                interfaces.append({
                    "id": iface,
                    "type": "interface",
                    "capabilities": caps
                })
        return interfaces

class ResourceManager:
    """Centralized manager for physical and virtual laboratory resources."""
    
    def __init__(self, db_manager: DatabaseManager):
        self.db = db_manager
        
    def sync_hardware(self):
        """Discovers local hardware and updates the DB registry."""
        ifaces = HardwareDiscovery.discover_linux_wifi_interfaces()
        
        with self.db.session_scope() as session:
            for iface in ifaces:
                res = session.query(Resource).filter_by(id=iface["id"]).first()
                if not res:
                    res = Resource(
                        id=iface["id"], 
                        resource_type=iface["type"],
                        capabilities=iface["capabilities"],
                        state=ResourceState.AVAILABLE
                    )
                    session.add(res)
                else:
                    # Update capabilities just in case
                    res.capabilities = iface["capabilities"]
                    
    def allocate(self, resource_id: str, experiment_id: str, required_caps: List[str] = None) -> bool:
        """Attempt to allocate a resource to an experiment."""
        with self.db.session_scope() as session:
            res = session.query(Resource).filter_by(id=resource_id).first()
            if not res:
                logger.error(f"Resource {resource_id} not found.")
                return False
                
            if res.state != ResourceState.AVAILABLE and res.current_experiment_id != experiment_id:
                logger.warning(f"Resource {resource_id} is not available (State: {res.state}).")
                return False
                
            if required_caps:
                for cap in required_caps:
                    if cap not in (res.capabilities or []):
                        logger.warning(f"Resource {resource_id} lacks required capability: {cap}")
                        return False
            
            res.state = ResourceState.ALLOCATED
            res.current_experiment_id = experiment_id
            return True

    def release(self, resource_id: str, experiment_id: str) -> bool:
        """Release a resource previously allocated to an experiment."""
        with self.db.session_scope() as session:
            res = session.query(Resource).filter_by(id=resource_id).first()
            if not res:
                return False
            if res.current_experiment_id == experiment_id:
                res.state = ResourceState.AVAILABLE
                res.current_experiment_id = None
                return True
            return False
            
    def release_all_for_experiment(self, experiment_id: str):
        """Release all resources tied to a specific experiment."""
        with self.db.session_scope() as session:
            resources = session.query(Resource).filter_by(current_experiment_id=experiment_id).all()
            for res in resources:
                res.state = ResourceState.AVAILABLE
                res.current_experiment_id = None
