from __future__ import annotations
import os
import subprocess
from typing import Any, Dict, List, Optional, Set

FORBIDDEN_NAMES = {'145', '145_v2', 'project', 'backup', 'copy'}

def validate_target_path(target_path: str, base_repo: Optional[str] = None) -> str:
    if base_repo is None:
        base_repo = os.path.abspath('.')
    abs_base = os.path.abspath(os.path.normpath(base_repo))
    abs_target = os.path.abspath(os.path.normpath(target_path))

    # Check that target is within canonical base repo
    if not abs_target.startswith(abs_base):
        raise ValueError(f'Target path {abs_target} is outside canonical repository {abs_base}')

    # Check for forbidden nested segments
    rel_path = os.path.relpath(abs_target, abs_base)
    parts = set(rel_path.replace('\\', '/').split('/'))
    for forbidden in FORBIDDEN_NAMES:
        if forbidden in parts:
            raise ValueError(f'Target path {abs_target} contains forbidden segment: {forbidden}')
    return abs_target

def detect_reparse_points_and_cycles(root_dir: str) -> Dict[str, Any]:
    visited_inodes: Set[Any] = set()
    reparse_points: List[str] = []
    cycle_detected = False

    for root, dirs, files in os.walk(root_dir, followlinks=False):
        for d in dirs:
            dir_path = os.path.join(root, d)
            if os.path.islink(dir_path):
                reparse_points.append(dir_path)
                try:
                    target = os.readlink(dir_path)
                    if os.path.abspath(target) == os.path.abspath(root_dir):
                        cycle_detected = True
                except Exception:
                    pass
    return {
        'reparse_points_found': len(reparse_points),
        'reparse_point_paths': reparse_points,
        'cycle_detected': cycle_detected,
    }

def audit_repository_structure(repo_root: Optional[str] = None) -> Dict[str, Any]:
    if repo_root is None:
        repo_root = os.path.abspath('.')
    abs_root = os.path.abspath(repo_root)
    violations: List[str] = []

    # 1. Git Top-level check
    try:
        top = subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], cwd=abs_root).decode('utf-8').strip()
        top_norm = os.path.normcase(os.path.abspath(top))
        root_norm = os.path.normcase(abs_root)
        if top_norm != root_norm:
            violations.append(f'Git toplevel {top} does not match audited root {abs_root}')
    except Exception as e:
        violations.append(f'Git rev-parse check failed: {e}')

    # 2. Branch check
    try:
        branch = subprocess.check_output(['git', 'branch', '--show-current'], cwd=abs_root).decode('utf-8').strip()
    except Exception:
        branch = 'unknown'

    # 3. Recursive .git check
    git_dirs: List[str] = []
    for root, dirs, files in os.walk(abs_root, topdown=True):
        if '.git' in dirs:
            git_dirs.append(os.path.abspath(os.path.join(root, '.git')))

    if len(git_dirs) != 1:
        violations.append(f'Expected exactly 1 .git directory, found {len(git_dirs)}: {git_dirs}')

    # 4. Forbidden root entries
    root_entries = os.listdir(abs_root)
    for forbidden in FORBIDDEN_NAMES:
        if forbidden in root_entries:
            violations.append(f'Found forbidden entry in workspace root: {forbidden}')

    # 5. Junction and cycle detection
    reparse_res = detect_reparse_points_and_cycles(abs_root)
    if reparse_res['cycle_detected']:
        violations.append('Recursive symlink/junction cycle detected in repository!')

    status = 'PASS' if len(violations) == 0 else 'FAIL'
    return {
        'status': status,
        'repository_root': abs_root,
        'git_branch': branch,
        'git_directories_count': len(git_dirs),
        'git_directories': git_dirs,
        'forbidden_entries_found': [e for e in root_entries if e in FORBIDDEN_NAMES],
        'reparse_points_count': reparse_res['reparse_points_found'],
        'reparse_points': reparse_res['reparse_point_paths'],
        'cycle_detected': reparse_res['cycle_detected'],
        'violations': violations,
    }
