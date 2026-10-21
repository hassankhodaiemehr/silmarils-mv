# SILMARILS Blockchain Demo

Interactive demonstration of **SILMARILS** for permissioned ledgers, with PQC comparison, TPS calculator, and QTL web UI.

## Paper simulation (canonical)

Section 9 numbers are generated from **`../simulation/`** (not this demo). Run:

```bash
cd ../simulation && python generate_paper_results.py
```

The QTL web demo may lag the paper; do not use it as the source of truth for IACR submission figures.

## Quick start (CLI)

```bash
cd demo
pip install -r requirements.txt
python run_demo.py --charts
```

## Web UI (QTL)

```bash
cd demo
pip install -r requirements.txt
uvicorn api:app --reload --port 8765
```

Open **http://localhost:8765**

## Docker deployment

```bash
cd demo
docker compose up --build -d
```

Demo available at **http://localhost:8765**

Production: deploy to Fly.io, Railway, or Azure Container Apps and set `demo_url` in the QTL Jekyll site.

## QTL website integration

The demo is embedded at **https://www.qtransitionlabs.com/demo/** via:

- `C:\Users\hassa\Projects\qtransitionlabs\silmarils-demo.md`
- Nav link **Demo** in `_includes/nav.html`
- `demo_url` in `_config.yml` (default: `http://localhost:8765`)

**Before publishing:** set production URL in `_config.yml`:

```yaml
demo_url: "https://demo.qtransitionlabs.com"
```

Then rebuild Jekyll:

```bash
cd qtransitionlabs
bundle exec jekyll build
```

## API endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Web UI |
| `GET /api/health` | Health check |
| `POST /api/sign` | Live SILMARILS sign/verify |
| `GET /api/compare` | Bandwidth + CPU comparison |
| `GET /api/tps` | TPS impact calculator |

## Features

- **Live crypto** — two-party TDV sign/verify + DV simulation + public `AuditVerify`
- **PQC comparison** — sizes vs Dilithium, Falcon, SPHINCS+
- **TPS calculator** — hybrid SILMARILS (~2%) vs full PQ retrofit (~87%)
- **QTL styling** — matches qtransitionlabs.com design tokens

## Important framing

SILMARILS is **not a Dilithium replacement**. It is **TDV** (designated verifier). Comparisons reflect efficiency where TDV semantics fit.
