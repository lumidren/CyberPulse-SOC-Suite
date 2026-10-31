"""
SOC Performance & Pipeline Telemetry Analytics Engine for CyberPulse
Calculates lab-measured MTTD, MTTA, MTTC and p50/p95/p99 latency distributions
from pipeline runs on emulated telemetry recorded in this process.
"""

import json
import math
import time
from datetime import datetime, timezone

def calculate_percentile(values, percentile):
    """Computes percentile from a list of numerical values"""
    if not values:
        return 0.0
    sorted_vals = sorted(values)
    k = (len(sorted_vals) - 1) * (percentile / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return round(sorted_vals[int(k)], 2)
    d0 = sorted_vals[int(f)] * (c - k)
    d1 = sorted_vals[int(c)] * (k - f)
    return round(d0 + d1, 2)

MEASUREMENT_BASIS = (
    "Lab-measured on emulated telemetry: in-process wall-clock timings of the "
    "simulated pipeline in this server process. Not production SOC latency."
)

NOT_MEASURED = "not yet measured"


class SOCMetricsEngine:
    def __init__(self):
        # No seeded history: every sample comes from a pipeline run in this process.
        self.detection_latencies = []
        self.intel_latencies = []
        self.containment_latencies = []
        self.total_pipeline_latencies = []

        self.total_events_processed = 0
        self.successful_detections = 0
        self.successful_containments = 0
        self.false_positives_recorded = 0

    def record_pipeline_execution(self, detection_ms, intel_ms, containment_ms, total_ms, detected=True, contained=True, is_fp=False):
        """Records a single pipeline execution into metric history"""
        self.total_events_processed += 1
        if detected:
            self.successful_detections += 1
            self.detection_latencies.append(detection_ms)
            self.intel_latencies.append(intel_ms)
            self.containment_latencies.append(containment_ms)
            self.total_pipeline_latencies.append(total_ms)
        if contained:
            self.successful_containments += 1
        if is_fp:
            self.false_positives_recorded += 1

    @staticmethod
    def _mean_sec(values_ms):
        if not values_ms:
            return NOT_MEASURED
        return round(sum(values_ms) / len(values_ms) / 1000.0, 4)

    @staticmethod
    def _pct(numerator, denominator):
        if denominator == 0:
            return NOT_MEASURED
        return round(numerator / denominator * 100.0, 1)

    def get_soc_metrics(self):
        """Computes lab pipeline metrics from samples recorded in this process.

        Any figure with no underlying samples is reported as "not yet measured"
        instead of a placeholder number.
        """
        samples = len(self.total_pipeline_latencies)

        def pct_sec(p):
            if not samples:
                return NOT_MEASURED
            return round(calculate_percentile(self.total_pipeline_latencies, p) / 1000.0, 4)

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "measurement_basis": MEASUREMENT_BASIS,
            "sample_count": samples,
            "operational_kpis": {
                "mttd_sec": self._mean_sec(self.detection_latencies),   # Mean Time to Detect (in-process)
                "mtta_sec": self._mean_sec(self.intel_latencies),       # Mean enrichment time (local cache)
                "mttc_sec": self._mean_sec(self.containment_latencies), # Mean simulated-containment time
                "total_mttp_sec": self._mean_sec(self.total_pipeline_latencies)
            },
            "latency_percentiles_sec": {
                "p50": pct_sec(50),
                "p90": pct_sec(90),
                "p95": pct_sec(95),
                "p99": pct_sec(99)
            },
            "reliability_rates": {
                "detection_success_rate_pct": self._pct(self.successful_detections, self.total_events_processed),
                "containment_success_rate_pct": self._pct(self.successful_containments, self.successful_detections),
                "false_positive_rate_pct": self._pct(self.false_positives_recorded, self.total_events_processed),
                "total_events_ingested": self.total_events_processed
            },
            "stage_breakdown_ms": {
                "detection_mttd_ms": round(sum(self.detection_latencies) / samples, 3) if samples else NOT_MEASURED,
                "enrichment_mtta_ms": round(sum(self.intel_latencies) / samples, 3) if samples else NOT_MEASURED,
                "containment_mttc_ms": round(sum(self.containment_latencies) / samples, 3) if samples else NOT_MEASURED
            }
        }

if __name__ == "__main__":
    engine = SOCMetricsEngine()
    print(json.dumps(engine.get_soc_metrics(), indent=2))
