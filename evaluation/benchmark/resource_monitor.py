"""Continuous System & Process Resource Monitor (Milestones 21 & 21.5).

Tracks:
- Process CPU % and System CPU %
- Process RSS Memory (MB), Peak RSS (MB), Memory Growth Rate (MB/minute)
- Memory Growth Audit & Classification: bounded_plateau, warmup_growth, persistent_growth, inconclusive
- Machine-readable resource & cardinality time series
- Active State Cardinalities: flows, entities, fusion states, open incidents, destinations, ports, domains, TLS JA3s
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import os
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import numpy as np
import psutil


@dataclass
class ResourceSample:
    """Point-in-time resource and state observation."""
    timestamp: float
    process_cpu_pct: float
    system_cpu_pct: float
    rss_mb: float
    active_flows: int = 0
    active_entities: int = 0
    active_fusion_states: int = 0
    active_incidents: int = 0
    unique_destinations: int = 0
    unique_ports: int = 0
    unique_domains: int = 0
    unique_fingerprints: int = 0


class ContinuousResourceMonitor:
    """Background daemon sampling host and pipeline resources continuously."""

    def __init__(
        self,
        sample_interval_sec: float = 0.1,
        state_callback: Optional[Callable[[], Dict[str, int]]] = None,
    ):
        self.sample_interval_sec = sample_interval_sec
        self.state_callback = state_callback
        self.process = psutil.Process(os.getpid())
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._samples: List[ResourceSample] = []
        self._lock = threading.Lock()
        self._initial_rss_mb = 0.0

    def start(self) -> None:
        """Start background resource sampling thread."""
        with self._lock:
            self._samples.clear()
            self._running = True
            # Prime CPU percentage counter
            self.process.cpu_percent(interval=None)
            psutil.cpu_percent(interval=None)
            self._initial_rss_mb = self.process.memory_info().rss / (1024 * 1024)

        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def _monitor_loop(self) -> None:
        """Background sampling loop."""
        while self._running:
            try:
                t_now = time.time()
                proc_cpu = self.process.cpu_percent(interval=None)
                sys_cpu = psutil.cpu_percent(interval=None)
                rss_mb = self.process.memory_info().rss / (1024 * 1024)

                active_flows = 0
                active_entities = 0
                active_fusion = 0
                active_inc = 0
                dst_count = 0
                port_count = 0
                dom_count = 0
                fp_count = 0

                if self.state_callback:
                    state = self.state_callback()
                    active_flows = state.get("active_flows", 0)
                    active_entities = state.get("active_entities", 0)
                    active_fusion = state.get("active_fusion_states", 0)
                    active_inc = state.get("active_incidents", 0)
                    dst_count = state.get("unique_destinations", 0)
                    port_count = state.get("unique_ports", 0)
                    dom_count = state.get("unique_domains", 0)
                    fp_count = state.get("unique_fingerprints", 0)

                sample = ResourceSample(
                    timestamp=t_now,
                    process_cpu_pct=proc_cpu,
                    system_cpu_pct=sys_cpu,
                    rss_mb=rss_mb,
                    active_flows=active_flows,
                    active_entities=active_entities,
                    active_fusion_states=active_fusion,
                    active_incidents=active_inc,
                    unique_destinations=dst_count,
                    unique_ports=port_count,
                    unique_domains=dom_count,
                    unique_fingerprints=fp_count,
                )

                with self._lock:
                    if len(self._samples) < 50000:
                        self._samples.append(sample)

            except Exception:
                pass

            time.sleep(self.sample_interval_sec)

    def stop(self) -> Dict[str, Any]:
        """Stop sampling and compile aggregate statistics and classification."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

        with self._lock:
            samples = list(self._samples)

        if not samples:
            curr_rss = self.process.memory_info().rss / (1024 * 1024)
            return {
                "sample_count": 0,
                "initial_rss_mb": round(self._initial_rss_mb, 2),
                "peak_rss_mb": round(curr_rss, 2),
                "mean_process_cpu_pct": 0.0,
                "p95_process_cpu_pct": 0.0,
                "max_process_cpu_pct": 0.0,
                "memory_growth_mb_per_min": 0.0,
                "memory_growth_classification": "inconclusive",
                "max_active_flows": 0,
                "max_active_entities": 0,
                "max_active_incidents": 0,
                "time_series": [],
            }

        proc_cpus = [s.process_cpu_pct for s in samples]
        rss_vals = [s.rss_mb for s in samples]
        flows = [s.active_flows for s in samples]
        entities = [s.active_entities for s in samples]
        incidents = [s.active_incidents for s in samples]
        dsts = [s.unique_destinations for s in samples]
        ports = [s.unique_ports for s in samples]
        doms = [s.unique_domains for s in samples]
        fps = [s.unique_fingerprints for s in samples]

        t0 = samples[0].timestamp
        duration_sec = max(1.0, samples[-1].timestamp - t0)
        growth_mb = max(0.0, rss_vals[-1] - rss_vals[0])
        growth_rate_per_min = (growth_mb / (duration_sec / 60.0)) if duration_sec > 0 else 0.0

        p95_cpu = sorted(proc_cpus)[int(len(proc_cpus) * 0.95)] if proc_cpus else 0.0

        # Memory Growth Classification
        if len(samples) < 5 or duration_sec < 1.0:
            classification = "inconclusive"
        else:
            t_rel = np.array([s.timestamp - t0 for s in samples])
            rss_arr = np.array(rss_vals)
            # Linear fit slope (MB / sec)
            if np.std(t_rel) > 1e-4:
                slope_mb_s, _ = np.polyfit(t_rel, rss_arr, 1)
                slope_mb_min = slope_mb_s * 60.0
            else:
                slope_mb_min = 0.0

            # Dynamic check
            rss_span = np.max(rss_arr) - np.min(rss_arr)
            if rss_span < 5.0 or abs(slope_mb_min) < 2.0:
                classification = "bounded_plateau"
            elif len(samples) >= 10:
                half = len(samples) // 2
                t_rel_late = t_rel[half:]
                rss_late = rss_arr[half:]
                slope_late_mb_s, _ = np.polyfit(t_rel_late, rss_late, 1)
                slope_late_mb_min = slope_late_mb_s * 60.0
                if abs(slope_late_mb_min) < 2.0:
                    classification = "warmup_growth"
                elif slope_late_mb_min > 5.0:
                    classification = "persistent_growth"
                else:
                    classification = "bounded_plateau"
            elif slope_mb_min > 5.0:
                classification = "persistent_growth"
            else:
                classification = "bounded_plateau"

        # Time series downsampled to at most 50 points
        step = max(1, len(samples) // 50)
        time_series = [
            {
                "time_sec": round(s.timestamp - t0, 2),
                "rss_mb": round(s.rss_mb, 2),
                "process_cpu_pct": round(s.process_cpu_pct, 1),
                "active_flows": s.active_flows,
                "active_entities": s.active_entities,
                "active_incidents": s.active_incidents,
            }
            for s in samples[::step]
        ]

        return {
            "sample_count": len(samples),
            "duration_sec": round(duration_sec, 2),
            "initial_rss_mb": round(self._initial_rss_mb, 2),
            "final_rss_mb": round(rss_vals[-1], 2),
            "peak_rss_mb": round(max(rss_vals), 2),
            "mean_process_cpu_pct": round(sum(proc_cpus) / len(proc_cpus), 2),
            "p95_process_cpu_pct": round(p95_cpu, 2),
            "max_process_cpu_pct": round(max(proc_cpus), 2),
            "mean_system_cpu_pct": round(sum(s.system_cpu_pct for s in samples) / len(samples), 2),
            "memory_growth_mb_per_min": round(growth_rate_per_min, 4),
            "memory_growth_classification": classification,
            "max_active_flows": max(flows) if flows else 0,
            "max_active_entities": max(entities) if entities else 0,
            "max_active_incidents": max(incidents) if incidents else 0,
            "max_unique_destinations": max(dsts) if dsts else 0,
            "max_unique_ports": max(ports) if ports else 0,
            "max_unique_domains": max(doms) if doms else 0,
            "max_unique_fingerprints": max(fps) if fps else 0,
            "memory_bounded_stable": (growth_mb < 25.0) or (growth_rate_per_min < 50.0),
            "time_series": time_series,
        }
