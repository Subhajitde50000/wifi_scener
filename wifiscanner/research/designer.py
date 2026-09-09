from typing import List, Dict, Any, Type
import logging

logger = logging.getLogger(__name__)

class Variable:
    def __init__(self, name: str, description: str, data_type: type):
        self.name = name
        self.description = description
        self.data_type = data_type
        
    def to_dict(self):
        return {
            "name": self.name,
            "description": self.description,
            "type": self.data_type.__name__
        }

class IndependentVariable(Variable):
    def __init__(self, name: str, description: str, data_type: type, levels: List[Any]):
        super().__init__(name, description, data_type)
        self.levels = levels

    def to_dict(self):
        d = super().to_dict()
        d["levels"] = self.levels
        d["kind"] = "independent"
        return d

class DependentVariable(Variable):
    def __init__(self, name: str, description: str, data_type: type, metrics: List[str] = None):
        super().__init__(name, description, data_type)
        self.metrics = metrics or []

    def to_dict(self):
        d = super().to_dict()
        d["metrics"] = self.metrics
        d["kind"] = "dependent"
        return d

class ControlledVariable(Variable):
    def __init__(self, name: str, description: str, data_type: type, value: Any):
        super().__init__(name, description, data_type)
        self.value = value

    def to_dict(self):
        d = super().to_dict()
        d["value"] = self.value
        d["kind"] = "controlled"
        return d

class ExperimentDesign:
    """A formal container for experiment design parameters."""
    
    def __init__(self, hypothesis: str = ""):
        self.hypothesis = hypothesis
        self.independent: List[IndependentVariable] = []
        self.dependent: List[DependentVariable] = []
        self.controlled: List[ControlledVariable] = []
        self.sample_size: int = 1
        self.repetitions: int = 1
        self.randomization_seed: Optional[int] = None
        
    def add_iv(self, iv: IndependentVariable):
        self.independent.append(iv)
        
    def add_dv(self, dv: DependentVariable):
        self.dependent.append(dv)
        
    def add_cv(self, cv: ControlledVariable):
        self.controlled.append(cv)

    def generate_matrix(self) -> List[Dict[str, Any]]:
        """Generates the experimental combinations (groups/trials)."""
        import itertools
        
        levels = [iv.levels for iv in self.independent]
        names = [iv.name for iv in self.independent]
        
        matrix = []
        for combo in itertools.product(*levels):
            trial = dict(zip(names, combo))
            # add controlled
            for cv in self.controlled:
                trial[cv.name] = cv.value
            matrix.append(trial)
            
        final_trials = []
        for rep in range(self.repetitions):
            for i, base_trial in enumerate(matrix):
                t = dict(base_trial)
                t["_repetition"] = rep + 1
                t["_group_id"] = i + 1
                final_trials.append(t)
                
        # Handle randomization
        if self.randomization_seed is not None:
            import random
            rng = random.Random(self.randomization_seed)
            rng.shuffle(final_trials)
            
        return final_trials

    def to_dict(self):
        return {
            "hypothesis": self.hypothesis,
            "sample_size": self.sample_size,
            "repetitions": self.repetitions,
            "randomization_seed": self.randomization_seed,
            "independent_variables": [v.to_dict() for v in self.independent],
            "dependent_variables": [v.to_dict() for v in self.dependent],
            "controlled_variables": [v.to_dict() for v in self.controlled]
        }
