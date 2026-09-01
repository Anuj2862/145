"""Benchmark Environment Profiler (Milestone 21).

Auto-discovers and records:
- CPU model, physical & logical core count, total & available RAM
- OS platform, architecture, release version
- Python runtime & compiler
- Key ML/data library dependencies (lightgbm, scikit-learn, joblib, numpy, pandas, psutil)
- Git commit hash & active branch
- Feature schema version and model versions
- Explicit recording of scikit-learn training version vs runtime version
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import importlib.metadata
import os
import platform
import subprocess
import sys
from typing import Any, Dict, Optional

import psutil

from features.model_features_v2 import MODEL_V2_FEATURE_SCHEMA_VERSION


@dataclass
class HardwareProfile:
    """Hardware specifications of the benchmark execution host."""
    cpu_model: str
    physical_cores: int
    logical_cores: int
    total_ram_gb: float
    available_ram_gb: float
    platform_name: str
    os_release: str
    os_version: str
    machine_arch: str


@dataclass
class SoftwareProfile:
    """Software stack and runtime dependencies."""
    python_version: str
    python_compiler: str
    python_executable: str
    installed_packages: Dict[str, str]
    sklearn_training_version: str = "1.8.0"
    sklearn_runtime_version: str = ""
    sklearn_version_mismatch_warning: str = ""


@dataclass
class RepositoryProfile:
    """Git repository metadata and versioned artifact contracts."""
    git_commit: str
    git_branch: str
    git_dirty: bool
    feature_schema_version: str = MODEL_V2_FEATURE_SCHEMA_VERSION
    model_version: str = "v2.1.0-calibrated-lgb"


@dataclass
class BenchmarkEnvironment:
    """Unified environment record for reproducible benchmarking."""
    recorded_at: str
    hardware: HardwareProfile
    software: SoftwareProfile
    repository: RepositoryProfile

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recorded_at": self.recorded_at,
            "hardware": asdict(self.hardware),
            "software": asdict(self.software),
            "repository": asdict(self.repository),
        }


class EnvironmentProfiler:
    """Collects comprehensive hardware, software, and repository telemetry."""

    @staticmethod
    def _get_cpu_model() -> str:
        """Retrieve human-readable CPU brand string across platforms."""
        try:
            if platform.system() == "Windows":
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
                )
                model, _ = winreg.QueryValueEx(key, "ProcessorNameString")
                winreg.CloseKey(key)
                return str(model).strip()
            elif platform.system() == "Linux":
                with open("/proc/cpuinfo", "r") as f:
                    for line in f:
                        if "model name" in line:
                            return line.split(":", 1)[1].strip()
            elif platform.system() == "Darwin":
                out = subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"])
                return out.decode("utf-8").strip()
        except Exception:
            pass
        return platform.processor() or "Unknown CPU"

    @staticmethod
    def _get_git_info() -> Dict[str, Any]:
        """Fetch git commit, branch, and status."""
        commit = "unknown"
        branch = "unknown"
        dirty = False
        try:
            commit = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL
            ).decode("utf-8").strip()
            branch = subprocess.check_output(
                ["git", "branch", "--show-current"], stderr=subprocess.DEVNULL
            ).decode("utf-8").strip()
            status = subprocess.check_output(
                ["git", "status", "--porcelain"], stderr=subprocess.DEVNULL
            ).decode("utf-8").strip()
            dirty = len(status) > 0
        except Exception:
            pass
        return {"commit": commit, "branch": branch, "dirty": dirty}

    @staticmethod
    def _get_package_version(pkg_name: str) -> str:
        """Safely fetch installed package version."""
        try:
            return importlib.metadata.version(pkg_name)
        except Exception:
            return "NOT_INSTALLED"

    @classmethod
    def capture_environment(cls) -> BenchmarkEnvironment:
        """Probe host environment and return structured metadata."""
        # Hardware
        mem = psutil.virtual_memory()
        hardware = HardwareProfile(
            cpu_model=cls._get_cpu_model(),
            physical_cores=psutil.cpu_count(logical=False) or 1,
            logical_cores=psutil.cpu_count(logical=True) or 1,
            total_ram_gb=round(mem.total / (1024 ** 3), 2),
            available_ram_gb=round(mem.available / (1024 ** 3), 2),
            platform_name=platform.system(),
            os_release=platform.release(),
            os_version=platform.version(),
            machine_arch=platform.machine(),
        )

        # Software
        core_packages = [
            "scikit-learn",
            "lightgbm",
            "joblib",
            "numpy",
            "pandas",
            "psutil",
            "fastapi",
            "uvicorn",
            "pytest",
        ]
        installed_pkgs = {pkg: cls._get_package_version(pkg) for pkg in core_packages}
        sklearn_runtime = installed_pkgs.get("scikit-learn", "unknown")
        sklearn_train = "1.8.0"
        mismatch_warn = ""
        if sklearn_runtime != sklearn_train and sklearn_runtime != "NOT_INSTALLED":
            mismatch_warn = (
                f"Model artifacts trained on scikit-learn {sklearn_train}; "
                f"evaluating on runtime {sklearn_runtime}. "
                "InconsistentVersionWarning preserved for evaluation integrity."
            )

        software = SoftwareProfile(
            python_version=platform.python_version(),
            python_compiler=platform.python_compiler(),
            python_executable=sys.executable,
            installed_packages=installed_pkgs,
            sklearn_training_version=sklearn_train,
            sklearn_runtime_version=sklearn_runtime,
            sklearn_version_mismatch_warning=mismatch_warn,
        )

        # Repository
        git_info = cls._get_git_info()
        repo = RepositoryProfile(
            git_commit=git_info["commit"],
            git_branch=git_info["branch"],
            git_dirty=git_info["dirty"],
            feature_schema_version=MODEL_V2_FEATURE_SCHEMA_VERSION,
            model_version="v2.1.0-calibrated-lgb",
        )

        return BenchmarkEnvironment(
            recorded_at=datetime.now(timezone.utc).isoformat(),
            hardware=hardware,
            software=software,
            repository=repo,
        )
