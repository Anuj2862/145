# Git Branching Strategy, Review Guidelines & Workflow

## 1. Branch Hierarchy

```text
main (Protected, Stable, Production & Demo-Ready)
  │
  ▼
integration (Active integration branch; all PRs target here)
  │
  ├── member-1/ingestion-flow
  ├── member-2/detection-ml
  └── member-3/entity-dashboard
```

### Branch Definitions
- **`main`:** The canonical, production-ready branch. Code on `main` has passed all integration tests, schema verifications, and milestone sign-offs. Direct commits to `main` are strictly prohibited.
- **`integration`:** The shared integration staging ground. Developers merge their feature work into `integration` via Pull Requests. End-to-end integration tests and pipeline benchmarks run here.
- **Member Feature Branches:**
  - `member-1/ingestion-flow`: Focused on `ingest/` and `flow/`.
  - `member-2/detection-ml`: Focused on `features/`, `detectors/`, and `evaluation/`.
  - `member-3/entity-dashboard`: Focused on `entity/`, `fusion/`, `evidence/`, `incidents/`, `api/`, and `dashboard/`.
  - Temporary sub-branches for specific tasks should follow: `<member>/<feature-name>` (e.g., `member-1/pcap-reader`, `member-2/dns-entropy`).

---

## 2. Commit Message Conventions
Follow the Conventional Commits specification:

```text
<type>(<scope>): <short summary>

[optional body explaining rationale]
```

### Allowed Types:
- `feat`: New feature or detector logic.
- `fix`: Bug fix in parsing, extraction, or scoring.
- `docs`: Documentation updates or additions.
- `schema`: Changes to data contracts (requires team-wide approval).
- `test`: Adding or modifying unit/integration tests.
- `refactor`: Code refactoring without behavioral change.
- `perf`: Performance optimization (throughput, latency, memory).

### Scope Examples:
`ingest`, `flow`, `features`, `detectors`, `entity`, `fusion`, `evidence`, `api`, `dashboard`, `evaluation`.

**Example:**  
`feat(flow): implement 5-second sliding window aggregator`  
`fix(detectors): correct SYN/ACK ratio calculation in volumetric detector`

---

## 3. Pull Request (PR) & Code Review Rules
1. **Target Branch:** All feature branches submit PRs to `integration` (never directly to `main`).
2. **Schema Protection:** If a PR touches `schemas/contracts.md` or serialized data structures, **all 3 members must approve** before merge.
3. **Automated Validation:** PRs must pass unit tests and schema validation without regression.
4. **Independent Scopes:** A member should not modify files outside their primary ownership area without prior coordination.
5. **Merge Strategy:** Prefer **Squash and Merge** or **Rebase and Merge** to maintain a clean, linear git history on `integration`.

---

## 4. Integration & Conflict Resolution Procedure
1. Before opening a PR, rebase the feature branch onto the latest `integration`:
   ```bash
   git fetch origin
   git checkout member-X/my-branch
   git rebase origin/integration
   ```
2. If conflicts occur:
   - Resolve conflicts locally.
   - Run tests to confirm integrity: `pytest tests/`.
   - Force-push to your feature branch: `git push origin member-X/my-branch --force-with-lease`.
3. Periodically, when an implementation milestone is fully verified on `integration`, a PR from `integration` $\rightarrow$ `main` is created and tagged with the milestone release (e.g., `v0.1.0-milestone1`).
