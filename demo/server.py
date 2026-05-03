"""demo/server.py — Real HTTP API in front of the real squash codebase.

Stdlib only beyond what squash already requires. CORS enabled so
``demo/index.html`` (loaded with ``file://`` or any origin) can hit the
endpoints during the demo.

Endpoints
---------

  GET  /                  → demo/index.html
  GET  /api/health        → version + collected test count
  POST /api/canon         → RFC 8785 canonical bytes + determinism proof
  POST /api/attest        → real squash attestation pipeline
  POST /api/verify        → real squash verification
  POST /api/self-verify   → real squash self-verify chain walker
  POST /api/genealogy     → real GenealogyBuilder over a known model family
  POST /api/copyright     → real CopyrightAnalyzer

Run::

    python demo/server.py            # binds 0.0.0.0:8002
    python demo/server.py --port 9001
    python demo/server.py --host 127.0.0.1

Make it Konjo.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
import threading
import time
import traceback
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# Make sure we always import the in-tree squash, not whatever pip installed.
_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
sys.path.insert(0, str(_REPO_ROOT))

import squash  # noqa: E402  -- after path mutation

log = logging.getLogger("squash.demo.server")


# ---------------------------------------------------------------------------
# Cached test count — collected once at startup; reused by /api/health.
# ---------------------------------------------------------------------------


def _collect_test_count() -> int:
    """Best-effort `pytest --collect-only` parse. 0 on failure."""
    try:
        import subprocess

        out = subprocess.run(
            [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(_REPO_ROOT),
        )
        for line in (out.stdout or "").splitlines():
            line = line.strip()
            # pytest emits e.g. "5355 tests collected in 17.95s"
            if "test" in line and "collected" in line:
                head = line.split()[0]
                if head.isdigit():
                    return int(head)
    except Exception:  # pragma: no cover - best-effort
        pass
    return 0


_TEST_COUNT_CACHE: dict[str, int] = {"value": 0}


# ---------------------------------------------------------------------------
# Endpoint implementations — every one calls real squash code.
# ---------------------------------------------------------------------------


def _api_health() -> dict:
    return {
        "ok": True,
        "version": getattr(squash, "__version__", "unknown"),
        "tests": _TEST_COUNT_CACHE.get("value", 0),
        "phase_g": True,
        "served_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _api_canon(body: dict) -> dict:
    """RFC 8785 canonical encoding + dict-order determinism proof."""
    from squash.canon import canonical_bytes, canonical_hash

    data = body.get("data")
    if data is None:
        return {"error": "missing 'data' field"}

    canonical = canonical_bytes(data)
    h = canonical_hash(data)

    proof_pair: list[dict] = []
    if isinstance(data, dict) and len(data) >= 2:
        # Reverse insertion order, prove same bytes.
        reversed_dict = dict(reversed(list(data.items())))
        rev_canonical = canonical_bytes(reversed_dict)
        proof_pair = [
            {"label": "as supplied", "canonical": canonical.decode("utf-8")},
            {"label": "keys reversed", "canonical": rev_canonical.decode("utf-8")},
        ]

    return {
        "canonical": canonical.decode("utf-8"),
        "bytes": len(canonical),
        "sha256": h,
        "deterministic_proof": proof_pair,
    }


def _api_attest(body: dict) -> dict:
    """Real squash attestation pipeline against a synthetic in-memory model."""
    from squash.attest import AttestConfig, AttestPipeline
    from squash.canon import canonical_bytes
    from squash.clock import FrozenClock, with_clock

    model_name = (body.get("model_name") or "demo-model").strip()[:64] or "demo-model"
    artifact_hash = (body.get("artifact_hash") or "").strip() or hashlib.sha256(
        model_name.encode()
    ).hexdigest()
    metadata = body.get("metadata") or {}
    if not isinstance(metadata, dict):
        metadata = {}

    work = Path(tempfile.mkdtemp(prefix="squash-server-"))
    model_dir = work / model_name.replace("/", "_")
    model_dir.mkdir()
    # Synthesise a tiny model file whose digest is deterministic from the
    # supplied artifact_hash. Anyone can re-derive the bytes.
    payload = artifact_hash.encode() * 16
    (model_dir / "model.safetensors").write_bytes(payload)
    (model_dir / "config.json").write_text(
        json.dumps({"name": model_name, **metadata}, indent=2, sort_keys=True)
    )

    clock = FrozenClock(datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc))
    t0 = time.perf_counter()
    try:
        with with_clock(clock):
            result = AttestPipeline.run(
                AttestConfig(
                    model_path=model_dir,
                    output_dir=model_dir,
                    policies=[],
                    fail_on_violation=False,
                    emit_input_manifest=True,
                )
            )
        elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)

        master_path = model_dir / "squash-attest.json"
        manifest_path = model_dir / "input_manifest.json"
        bom_path = model_dir / "cyclonedx-mlbom.json"

        attestation = json.loads(master_path.read_text()) if master_path.exists() else {}
        manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
        bom = json.loads(bom_path.read_text()) if bom_path.exists() else {}

        # Sign the canonical attestation bytes with a demo HMAC key.
        sig_payload = canonical_bytes(attestation)
        demo_key = b"squash-demo-key-do-not-use-in-prod"
        signature = hashlib.sha256(demo_key + sig_payload).hexdigest()

        return {
            "ok": True,
            "attestation": attestation,
            "input_manifest_summary": {
                "schema": manifest.get("schema"),
                "file_count": manifest.get("file_count"),
                "total_bytes": manifest.get("total_bytes"),
                "manifest_sha256": manifest.get("manifest_sha256"),
            },
            "bom_summary": {
                "format": bom.get("bomFormat"),
                "spec_version": bom.get("specVersion"),
                "serial_number": bom.get("serialNumber"),
                "components": len(bom.get("components", [])) if isinstance(bom, dict) else 0,
            },
            "signature_b64": base64.b64encode(bytes.fromhex(signature)).decode("ascii"),
            "canonical_json_bytes": len(sig_payload),
            "latency_ms": elapsed_ms,
            "result_passed": bool(result.passed),
        }
    finally:
        # Keep the dir around for /api/verify? No — return enough fields
        # in the response that a verify call can stand alone.
        try:
            shutil.rmtree(work)
        except Exception:  # pragma: no cover
            pass


def _api_verify(body: dict) -> dict:
    """Re-canonicalise the supplied attestation and check field-level
    invariants. Stateless: the cert is whatever the client sends."""
    from squash.canon import canonical_bytes, canonical_hash

    attestation = body.get("attestation") or {}
    if not isinstance(attestation, dict):
        return {"error": "attestation must be a JSON object"}

    t0 = time.perf_counter()
    checks_passed: list[str] = []
    checks_failed: list[str] = []

    # 1. Round-trip stability.
    try:
        cb = canonical_bytes(attestation)
        cb2 = canonical_bytes(json.loads(cb.decode("utf-8")))
        if cb == cb2:
            checks_passed.append("canonical re-encode is byte-stable")
        else:
            checks_failed.append("canonical re-encode drift")
    except Exception as exc:
        checks_failed.append(f"canonical encode failed: {exc}")

    # 2. Required-fields presence.
    required = {"squash_version", "model_id", "attested_at", "passed"}
    missing = sorted(required - set(attestation.keys()))
    if not missing:
        checks_passed.append("required fields present")
    else:
        checks_failed.append(f"missing fields: {', '.join(missing)}")

    # 3. attested_at parseable + UTC.
    try:
        ts = attestation.get("attested_at", "")
        if ts.endswith("Z"):
            datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
            checks_passed.append("attested_at is RFC 3339 UTC")
        else:
            checks_failed.append("attested_at not Z-suffixed UTC")
    except Exception as exc:
        checks_failed.append(f"attested_at unparseable: {exc}")

    # 4. SHA-256 of canonical body.
    body_sha = canonical_hash(attestation)

    # 5. Optional input_manifest_sha256 sanity.
    if "input_manifest_sha256" in attestation:
        if isinstance(attestation["input_manifest_sha256"], str) and len(attestation["input_manifest_sha256"]) == 64:
            checks_passed.append("input_manifest_sha256 well-formed")
        else:
            checks_failed.append("input_manifest_sha256 malformed")

    elapsed = round((time.perf_counter() - t0) * 1000, 3)
    return {
        "valid": len(checks_failed) == 0,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "body_sha256": body_sha,
        "latency_ms": elapsed,
    }


def _api_self_verify(_body: dict) -> dict:
    """Run the chain walker against a fresh in-memory attestation dir.

    Demonstrates what `squash self-verify` does locally — without
    depending on whatever the client may or may not have on disk.
    """
    from squash.attest import AttestConfig, AttestPipeline
    from squash.clock import FrozenClock, with_clock
    from squash.self_verify import verify

    work = Path(tempfile.mkdtemp(prefix="squash-self-verify-"))
    model_dir = work / "demo-model"
    model_dir.mkdir()
    (model_dir / "weights.bin").write_bytes(b"\x00" * 1024)
    (model_dir / "config.json").write_text('{"name":"demo"}')

    try:
        with with_clock(FrozenClock(datetime(2026, 5, 1, tzinfo=timezone.utc))):
            AttestPipeline.run(
                AttestConfig(
                    model_path=model_dir,
                    output_dir=model_dir,
                    policies=[],
                    fail_on_violation=False,
                )
            )
        report = verify(model_dir, offline=True)
        return {
            "overall": "pass" if report.passed else "fail",
            "checks": [
                {"name": c.name, "result": "pass" if c.passed else "fail", "detail": c.detail}
                for c in report.checks
            ],
        }
    finally:
        try:
            shutil.rmtree(work)
        except Exception:  # pragma: no cover
            pass


def _api_genealogy(body: dict) -> dict:
    """Run the real GenealogyBuilder against a synthesised model dir whose
    config maps to a known family in ``squash.genealogy._BASE_MODEL_REGISTRY``."""
    from squash.genealogy import GenealogyBuilder

    requested = (body.get("model_name") or "llama").strip().lower()[:64] or "llama"
    # Keep things safe — map free-text input to one of the known seeds.
    aliases = {
        "llama": "meta-llama/Llama-2-7b",
        "llama-2": "meta-llama/Llama-2-7b",
        "llama-3": "meta-llama/Meta-Llama-3-8B",
        "gpt-2": "gpt2",
        "mistral": "mistralai/Mistral-7B-v0.1",
        "mixtral": "mistralai/Mixtral-8x7B-v0.1",
        "falcon": "tiiuae/falcon-7b",
        "bloom": "bigscience/bloom",
        "qwen": "Qwen/Qwen2-7B",
        "gemma": "google/gemma-7b",
    }
    seed = aliases.get(requested, requested)

    work = Path(tempfile.mkdtemp(prefix="squash-gen-"))
    model_dir = work / requested.replace("/", "_")
    model_dir.mkdir()
    (model_dir / "config.json").write_text(json.dumps({"_name_or_path": seed}))

    try:
        report = GenealogyBuilder().build(
            model_dir, deployment_domain="content-generation"
        )
        chain = report.chain
        # Aggregate dataset composition for the donut chart.
        counts: dict[str, int] = {}
        for n in chain.nodes:
            for d in n.datasets:
                counts[d] = counts.get(d, 0) + 1
        composition = sorted(
            ({"label": k, "weight": v} for k, v in counts.items()),
            key=lambda r: -r["weight"],
        )[:8]
        return {
            "model_id": report.model_id,
            "families": [n.model_family for n in chain.nodes],
            "depth": chain.depth,
            "root_family": chain.root_model_family,
            "contamination_verdict": report.contamination_verdict,
            "copyright_risk": report.copyright_risk_tier,
            "copyright_score": report.copyright_risk_score,
            "training_composition": composition,
            "copyright_sources": chain.worst_copyright_sources()[:8],
            "nodes": [
                {
                    "step": i + 1,
                    "type": n.step_type,
                    "model": n.base_model or n.node_id,
                    "datasets": list(n.datasets),
                    "risk": n.copyright_risk,
                }
                for i, n in enumerate(chain.nodes)
            ],
            "signature": report.signature[:24] + "…" if report.signature else "",
        }
    finally:
        try:
            shutil.rmtree(work)
        except Exception:  # pragma: no cover
            pass


def _api_copyright(body: dict) -> dict:
    """Run the real CopyrightAnalyzer over a synthesised model whose
    declared licences match the request."""
    from squash.copyright import CopyrightAnalyzer

    licenses_in = body.get("licenses") or ["Apache-2.0", "MIT"]
    if not isinstance(licenses_in, list) or not licenses_in:
        licenses_in = ["Apache-2.0", "MIT"]
    model_lic = str(licenses_in[0])[:40]
    data_licenses = [str(x)[:40] for x in licenses_in[1:]] or [model_lic]
    use = (body.get("deployment_use") or "commercial").strip().lower()
    if use not in ("commercial", "research", "internal"):
        use = "commercial"

    work = Path(tempfile.mkdtemp(prefix="squash-cpr-"))
    model_dir = work / "copyright-demo"
    model_dir.mkdir()
    (model_dir / "README.md").write_text(f"license: {model_lic}\n\nDemo.\n")
    (model_dir / "squash-attest.json").write_text(
        json.dumps(
            {
                "model_id": "demo-corpus",
                "license": model_lic,
                "training_dataset_ids": data_licenses,
            }
        )
    )

    try:
        report = CopyrightAnalyzer().analyze(model_dir, deployment_use=use)
        return {
            "model_id": report.model_id,
            "deployment_use": report.deployment_use,
            "compatible": report.compatible,
            "risk_tier": report.risk_tier,
            "risk_score": report.risk_score,
            "model_license": {
                "spdx_id": report.model_license.spdx_id,
                "category": str(report.model_license.category),
                "commercial_ok": report.model_license.commercial_ok,
            },
            "training_data_licenses": [
                {
                    "spdx_id": l.spdx_id,
                    "category": str(l.category),
                    "commercial_ok": l.commercial_ok,
                    "source": l.source,
                }
                for l in report.training_data_licenses[:8]
            ],
            "compatibility_issues": [
                {
                    "severity": getattr(i, "severity", "?"),
                    "description": getattr(i, "description", str(i))[:200],
                }
                for i in report.compatibility_issues[:8]
            ],
            "recommendations": [r[:200] for r in report.recommendations[:5]],
            "verdict": (
                "Compatible for " + use
                if report.compatible
                else (
                    "NOT compatible for " + use
                    if report.compatible is False
                    else "Uncertain — review needed"
                )
            ),
            "signature": report.signature[:24] + "…" if report.signature else "",
        }
    finally:
        try:
            shutil.rmtree(work)
        except Exception:  # pragma: no cover
            pass


# ---------------------------------------------------------------------------
# HTTP handler
# ---------------------------------------------------------------------------


_ROUTES_POST = {
    "/api/canon":       _api_canon,
    "/api/attest":      _api_attest,
    "/api/verify":      _api_verify,
    "/api/self-verify": _api_self_verify,
    "/api/genealogy":   _api_genealogy,
    "/api/copyright":   _api_copyright,
}


class DemoHandler(BaseHTTPRequestHandler):
    server_version = f"squash-demo/{getattr(squash, '__version__', '0')}"

    # Quieter logs — show requests on a single line.
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        log.info("%s - " + fmt, self.address_string(), *args)

    def _set_cors(self) -> None:
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "300")

    def _write_json(self, status: int, body: dict) -> None:
        payload = json.dumps(body, indent=2, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self._set_cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _write_file(self, status: int, body: bytes, ctype: str) -> None:
        self.send_response(status)
        self._set_cors()
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:  # noqa: N802 - HTTP verb
        self.send_response(HTTPStatus.NO_CONTENT)
        self._set_cors()
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - HTTP verb
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            html = (_HERE / "index.html").read_bytes()
            self._write_file(HTTPStatus.OK, html, "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._write_json(HTTPStatus.OK, _api_health())
            return
        if path.startswith("/api/"):
            self._write_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "use POST"})
            return
        self._write_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802 - HTTP verb
        path = urlparse(self.path).path
        handler = _ROUTES_POST.get(path)
        if handler is None:
            self._write_json(HTTPStatus.NOT_FOUND, {"error": "no such endpoint"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length > 0 else b"{}"
            body = json.loads(raw.decode("utf-8") or "{}")
            result = handler(body)
            self._write_json(HTTPStatus.OK, result)
        except json.JSONDecodeError as exc:
            self._write_json(HTTPStatus.BAD_REQUEST, {"error": f"invalid JSON: {exc}"})
        except Exception as exc:  # noqa: BLE001 - demo surface
            log.exception("handler crash on %s", path)
            self._write_json(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": str(exc), "trace": traceback.format_exc().splitlines()[-3:]},
            )


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--host", default="0.0.0.0", help="Bind address (default 0.0.0.0).")
    p.add_argument("--port", type=int, default=8002, help="Port (default 8002).")
    p.add_argument("--quiet", action="store_true", help="Suppress per-request log lines.")
    p.add_argument("--skip-collect", action="store_true", help="Skip pytest --collect-only at startup.")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.WARNING if args.quiet else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )

    # Collect tests once in the background so /api/health is fast.
    if not args.skip_collect:
        def _collect_async() -> None:
            _TEST_COUNT_CACHE["value"] = _collect_test_count()
            log.info("test count: %d", _TEST_COUNT_CACHE["value"])

        threading.Thread(target=_collect_async, daemon=True).start()

    httpd = ThreadingHTTPServer((args.host, args.port), DemoHandler)
    print(
        f"\n  Squash demo server running at http://{args.host}:{args.port}\n"
        f"  Open http://localhost:{args.port}/ in a browser.\n"
        f"  Press Ctrl+C to stop.\n"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n  shutting down…")
    finally:
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
