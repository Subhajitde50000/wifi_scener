from typing import List, Dict, Any

class AnalyzerSDK:
    """Base interface for developing custom post-experiment analytical processes."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
    def analyze(self, dataset_id: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Process the provided event/capture dataset and generate insights.
        Must return a structured dictionary representing the analysis report.
        """
        raise NotImplementedError("Analyzers must implement analyze()")


class DatasetProcessorSDK:
    """Base interface for building custom dataset cleaning/filtering pipelines."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
    def process(self, raw_data: List[Any]) -> List[Any]:
        """
        Takes in raw capture frames, database logs, or API responses,
        cleans them, handles missing values, and returns the purified dataset.
        """
        raise NotImplementedError("Dataset processors must implement process()")
