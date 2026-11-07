# Collaboration guide — Person A (Linux) & Person B (macOS)

## Git workflow
- `main` is the integration branch. Nobody commits directly to `main` after the skeleton.
- Person A works on `person-a/backend` (or `person-a/<topic>`); Person B on
  `person-b/<topic>`.
- Merge into `main` via PR (or `git merge --no-ff`) once your slice passes:
  `.venv/bin/python -m pytest tests/ -q` and your half of `./demo.sh`.
- Commit style: `area: short imperative` (e.g. `stores: add CRLSet parser`,
  `web: red/green store cards on dashboard`).
- Push to a shared remote when one is added: `git remote add origin <url>`.

## Setup on your machine
```bash
git clone <remote> && cd rootcanal
git checkout -b person-a/backend        # or person-b/...
python3 -m venv .venv                   # macOS: may need `brew install python3`
.venv/bin/pip install -e .[dev]
```
Notes: `.venv/` is gitignored (per-OS). `.gitattributes` forces LF, so `demo.sh` works
on both platforms. On macOS, `certutil` is usually absent — the Firefox store must use
its JSON-mirror fallback (contract in `catrust/stores/firefox.py`).

## Working with AI tools
- `AGENTS.md` at the repo root is read automatically by OpenCode / Claude Code / Cursor.
  It contains the project rules, the shared contracts, and the file-ownership boundary.
- When prompting an AI tool, say which person you are: "You are Person A…" — the ownership
  rules in `AGENTS.md` then apply. Your orders are in `docs/PERSON-A.md` / `docs/PERSON-B.md`.
- Never let an AI tool change contract signatures (`stores/base.py`, `probes.py`,
  `manager.py`, `pki.py`, `server.py` headers) without updating BOTH `docs/PERSON-*.md`.

## Integration checkpoints
- After A's backend lands: `pytest` green; `cli setup && cli serve & cli probe` shows
  ACCEPT pre-remediate and REJECT post-remediate.
- After B's web UI lands: `rootcanal web --port 8080` shows red cards → remediate → green.
- Final: `./demo.sh` end-to-end in the sandbox, then a live web UI run for judges.
