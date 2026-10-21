FROM python:3.12-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8765

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api.py demo_service.py blockchain_sim.py pqc_catalog.py silmarils_core.py tps_calculator.py ./
COPY web/ ./web/

EXPOSE 8765

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8765\")}/api/health')"

CMD uvicorn api:app --host 0.0.0.0 --port ${PORT:-8765}
