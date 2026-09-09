import importlib
import inspect
from typing import Dict, Type

from .benchmark import DetectorInterface
from .sdk import AnalyzerSDK, DatasetProcessorSDK

class PluginManager:
    """Dynamically loads research extensions (Detectors, Analyzers, Processors)."""
    
    def __init__(self):
        self.detectors: Dict[str, Type[DetectorInterface]] = {}
        self.analyzers: Dict[str, Type[AnalyzerSDK]] = {}
        self.processors: Dict[str, Type[DatasetProcessorSDK]] = {}

    def load_from_module(self, module_name: str) -> Dict[str, int]:
        """
        Dynamically imports a Python module and indexes all subclasses of 
        the research SDK interfaces.
        Returns the counts of loaded plugins.
        """
        try:
            mod = importlib.import_module(module_name)
        except ImportError as e:
            raise RuntimeError(f"Failed to load plugin module {module_name}: {e}")
            
        counts = {"detectors": 0, "analyzers": 0, "processors": 0}
            
        for name, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, DetectorInterface) and obj is not DetectorInterface:
                self.detectors[name] = obj
                counts["detectors"] += 1
            elif issubclass(obj, AnalyzerSDK) and obj is not AnalyzerSDK:
                self.analyzers[name] = obj
                counts["analyzers"] += 1
            elif issubclass(obj, DatasetProcessorSDK) and obj is not DatasetProcessorSDK:
                self.processors[name] = obj
                counts["processors"] += 1
                
        return counts
        
    def get_detector(self, name: str, config: Dict = None) -> DetectorInterface:
        if name not in self.detectors:
            raise KeyError(f"Detector {name} not found.")
        return self.detectors[name](config)
        
    def get_analyzer(self, name: str, config: Dict = None) -> AnalyzerSDK:
        if name not in self.analyzers:
            raise KeyError(f"Analyzer {name} not found.")
        return self.analyzers[name](config)
        
    def get_processor(self, name: str, config: Dict = None) -> DatasetProcessorSDK:
        if name not in self.processors:
            raise KeyError(f"Processor {name} not found.")
        return self.processors[name](config)
