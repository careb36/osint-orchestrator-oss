# Demo seed

Runs shown by the public demo before any visitor starts one. This folder ships
empty: seed files are produced by the maintainer from real runs.

- One JSON file per run, written by `scripts/export_demo_seed.py`. A seed holds
  the run's metadata, the evidence qualifications, the run's Markdown and JSON
  files with the report's synthesis section removed, and which model
  synthesised the run. It holds no synthesis text, no risk assessment, no
  signature, no key and no raw model response.
- On startup with `DEMO_MODE=true`, the files are imported once, when no
  allowlisted target has a run yet. Each run gets a new id and directory and is
  sealed again with this deployment's `ORCHESTRATOR_SECRET_KEY`, so it verifies
  with `GET /demo/targets/{id}/chain/verify` like a run made here.
- A seed is only imported for a target id present in `demo/targets.demo.yaml`.
- Files are imported in name order; name them so runs of one target sort
  oldest first (for example `acme-01.json`, `acme-02.json`).

```bash
python scripts/export_demo_seed.py --database ./orchestrator.db --run-id 12 > demo/seed/acme-01.json
```

Review a seed before committing it: it is published with the repository.
