"""FastAPI backend for the SILMARILS web demo."""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from demo_service import build_comparison, catalog_schemes, run_live_flow
from tps_calculator import build_tps_comparison

WEB_DIR = Path(__file__).resolve().parent / "web"

app = FastAPI(
    title="SILMARILS Demo API",
    description="Interactive blockchain + PQC comparison demo for QTL / EternaX sites.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class SignRequest(BaseModel):
    message: str = Field(
        default='{"from":"alice","to":"bob","amount":100,"nonce":42}',
        max_length=4096,
    )


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/catalog")
def get_catalog() -> list[dict]:
    return catalog_schemes()


@app.post("/api/sign")
def post_sign(body: SignRequest) -> dict:
    result = run_live_flow(body.message)
    return {
        "message": result.message,
        "real_verify": result.real_verify,
        "simulated_verify": result.simulated_verify,
        "signature_bytes": result.signature_bytes,
        "receipt": result.receipt,
        "timing_us": {"sign": result.sign_us, "verify": result.verify_us},
    }


@app.get("/api/compare")
def get_compare(
    validators: int = Query(7, ge=3, le=100),
    tx_per_block: int = Query(500, ge=50, le=10000),
    blocks_per_minute: float = Query(2.0, ge=0.1, le=60.0),
    consensus_rounds_per_block: int = Query(3, ge=1, le=10),
) -> dict:
    payload = build_comparison(
        validators=validators,
        tx_per_block=tx_per_block,
        blocks_per_minute=blocks_per_minute,
        consensus_rounds_per_block=consensus_rounds_per_block,
    )
    return {
        "ledger_config": payload.ledger_config,
        "schemes": payload.schemes,
        "hybrid_deployment": payload.hybrid_deployment,
        "highlights": payload.highlights,
    }


@app.get("/api/tps")
def get_tps(
    base_tps: int = Query(10000, ge=1000, le=200000),
    validators: int = Query(7, ge=3, le=100),
    tx_per_block: int = Query(500, ge=50, le=10000),
    blocks_per_minute: float = Query(2.0, ge=0.1, le=60.0),
    consensus_rounds_per_block: int = Query(3, ge=1, le=10),
    block_auth_cap_bytes: int = Query(262144, ge=65536, le=4_194_304),
    network_mbps: float = Query(100.0, ge=1.0, le=10_000.0),
) -> dict:
    return build_tps_comparison(
        base_tps=base_tps,
        validators=validators,
        tx_per_block=tx_per_block,
        blocks_per_minute=blocks_per_minute,
        consensus_rounds_per_block=consensus_rounds_per_block,
        block_auth_cap_bytes=block_auth_cap_bytes,
        network_mbps=network_mbps,
    )


@app.get("/")
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


app.mount("/assets", StaticFiles(directory=WEB_DIR), name="assets")
