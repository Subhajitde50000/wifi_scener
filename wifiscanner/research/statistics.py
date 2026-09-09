import math
from typing import List, Dict, Any, Tuple

class Statistics:
    """Statistical functions for analyzing dependent variables across experiment groups."""

    @staticmethod
    def mean(values: List[float]) -> float:
        if not values:
            return 0.0
        return sum(values) / len(values)

    @staticmethod
    def median(values: List[float]) -> float:
        if not values:
            return 0.0
        s = sorted(values)
        n = len(s)
        if n % 2 == 1:
            return s[n // 2]
        return (s[n // 2 - 1] + s[n // 2]) / 2.0

    @staticmethod
    def variance(values: List[float], sample: bool = True) -> float:
        if len(values) < 2:
            return 0.0
        m = Statistics.mean(values)
        sq = sum((x - m) ** 2 for x in values)
        return sq / (len(values) - (1 if sample else 0))

    @staticmethod
    def std_dev(values: List[float], sample: bool = True) -> float:
        return math.sqrt(Statistics.variance(values, sample))

    @staticmethod
    def confidence_interval(values: List[float], z_score: float = 1.96) -> Tuple[float, float, float]:
        """Returns (mean, lower_bound, upper_bound) assuming a normal distribution."""
        n = len(values)
        if n == 0:
            return 0.0, 0.0, 0.0
        if n == 1:
            return values[0], values[0], values[0]
            
        m = Statistics.mean(values)
        s = Statistics.std_dev(values)
        margin = z_score * (s / math.sqrt(n))
        return m, m - margin, m + margin

    @staticmethod
    def summary(values: List[float]) -> Dict[str, float]:
        """Provides a complete descriptive summary."""
        if not values:
            return {"count": 0}
        n = len(values)
        m = Statistics.mean(values)
        return {
            "count": n,
            "min": min(values),
            "max": max(values),
            "mean": m,
            "median": Statistics.median(values),
            "std_dev": Statistics.std_dev(values),
            "variance": Statistics.variance(values)
        }
