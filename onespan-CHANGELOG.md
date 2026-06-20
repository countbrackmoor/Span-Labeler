# Changelog — OneSpan

Browser-based span-labeling annotation tool for multi-turn chatbot conversations. FastAPI backend, deployed via Kubeflow/JupyterLab.

---

## ~2026-06-02 — Full build (single extended session)

Built end-to-end across one long session. Captured below as logical groupings in roughly the order they were tackled.

### Added (UI foundation)
- Single-file HTML/CSS/JS frontend
- Drag-to-reorder label categories
- Annotation guidelines panel as the default sidebar tab
- Editable dataset metadata and label properties
- Editable notes after submission
- Last-updated timestamp on dataset cards
- Keyboard shortcuts (1–9, a–z) for labeling
- Conversation completion tracking; jump to next incomplete with `N`
- Overlapping spans supported

### Added (span relations)
- Directed SVG arrows between spans to capture relationships (e.g. AMOUNT → TRANSFER intent)

### Changed (UI polish)
- Metrics section sizing corrected
- Dark mode contrast fixed in Manage Labels workflow
- Category header text colors fixed
- Input fields: white background, black text; colored label chips preserved

### Removed
- Redundant Labels sidebar tab

### Added (export formats — expanded from 1 to 7)
- OneSpan JSON
- HuggingFace JSONL
- CoNLL-2003
- BIO tagging
- BIOES tagging
- spaCy v3 JSON
- CSV

### Added (Review mode)
- Admin-only read-only view of any annotator's spans
- Annotator switcher

### Changed (architecture: localStorage → shared server)
- Migrated storage to `dataset.json` on a FastAPI server (`server.py` + `index.html`)
- Atomic writes via `.tmp` + rename — crash-safe
- Write lock so concurrent saves queue rather than race
- Debounced saves

### Fixed (JupyterLab proxy compatibility)
- Switched from absolute URLs (`/data`) to relative URLs (`data`)
- Parse request bodies from raw bytes rather than relying on `Content-Type` header
- Use session cookies for auth (7-day TTL)
- Resolves 403 errors and URL resolution problems behind the corporate proxy

### Added (authentication)
- Per-annotator login (Option B chosen over alternatives)
- PBKDF2-SHA256 password hashing
- Admin-only account provisioning
- Per-dataset access control
- Existing `abc12345` annotator ID format preserved
- Default admin: username `admin`, password `spann3r$` (changeable via Admin panel)
- Full admin panel for provisioning, password resets, dataset access

### Added (time tracking)
- Active annotation time tracking with configurable idle threshold (default 4 minutes, adjustable in admin settings)
- 30-second heartbeat flushes
- Per-dataset and cross-dataset time metrics, admin-only

### Added (demo mode)
- `DEMO_MODE=true` env flag bypasses login
- All reads/writes isolated to `demo_dataset.json`

### Added (metrics)
- Cohen's κ, Krippendorff's α, Fleiss' κ
- Per-label precision / recall / F1
- Label distribution and span statistics
- Admin-only access

### Final scale
- ~6,100 lines HTML/CSS/JS (single-file frontend)
- ~480 lines Python (FastAPI server)
- 108 JS functions
- 11 REST API endpoints
- No external libs beyond FastAPI and uvicorn

### Added (deployment notes)
- Two-file deploy: `server.py` + `index.html`, plus `dataset.json` on disk
- Started via `python server.py` in JupyterLab terminal; accessed through JupyterLab proxy URL
