"""Pytest root configuration file for UniGuard test suite.

Ensures lightgbm C extension initializes before sklearn/scipy BLAS handles on Windows
to prevent DLL initialization order pointer table corruption (access violation reading 0x0).
"""

try:
    import lightgbm as lgb
except ImportError:
    pass
