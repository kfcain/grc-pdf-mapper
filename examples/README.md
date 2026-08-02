# Examples

Static gallery of sample outputs from the toolkit.

## View in a browser

```bash
# from repo root
bash examples/generate_viewer_data.sh
python3 -m http.server 8765 --directory examples/viewer
```

Open [http://127.0.0.1:8765](http://127.0.0.1:8765).

The gallery shows:

- Document change impact alerts
- Policy-as-code completeness and IaC-change prompts
- FedRAMP CR26 KSI listings for Classes A–D

## Scripts

| Path | Role |
|---|---|
| `examples/viewer/` | Static HTML gallery |
| `examples/generate_viewer_data.sh` | Rebuild `viewer/data/` samples |
| `examples/demo.sh` | CLI lineage demo |
| `examples/demo_alerts.sh` | Impact alert demo |
