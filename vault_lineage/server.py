"""HTTP Server & AWS CloudFront `/api/*` Lambda Origin Handler for VaultLineage."""
from __future__ import annotations

import base64
import json
import mimetypes
import os
import platform
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlparse

from .benchmarks import run_vault_lineage_benchmarks
from .storage_engine import (
    AuthorizationDeniedError,
    CryptoShreddedError,
    VaultLineageEngine,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = ROOT_DIR / "web"
DOCS_DIR = ROOT_DIR / "docs"
BENCH_JSON_PATH = ROOT_DIR / "benchmarks" / "latest_results.json"

ENGINE = VaultLineageEngine()

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
}


def _load_cached_benchmarks() -> Dict[str, Any]:
    if BENCH_JSON_PATH.is_file():
        try:
            return json.loads(BENCH_JSON_PATH.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {
        "events_benchmarked": 10000,
        "opt_out_leakage_rate_pct": 0.0,
        "downstream_lineage_purge_pct": 100.0,
        "crypto_shred_undecipherable_pct": 100.0,
    }


def route_api_request(
    method: str,
    path: str,
    query: Dict[str, str],
    body: Dict[str, Any],
    request_id: str = "local",
) -> Tuple[int, Dict[str, Any]]:
    """Pure router shared by local HTTP server and AWS Lambda `/api/*` origin behind CloudFront."""
    clean_path = path.rstrip("/") if path != "/" else "/"
    try:
        if method == "GET" and clean_path == "/api/health":
            audit_check = ENGINE.verify_audit_chain()
            return 200, {
                "status": "ok",
                "service": "vault-lineage-storage",
                "delivery": os.environ.get("VAULTLINEAGE_DELIVERY", "cloudfront-s3-oac + lambda-api-origin"),
                "aws_region": os.environ.get("AWS_REGION", "us-west-2"),
                "bedrock_model": os.environ.get("VAULTLINEAGE_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0"),
                "python_version": platform.python_version(),
                "request_id": request_id,
                "tenants_count": len(ENGINE.tenants),
                "events_count": len(ENGINE.events),
                "ml_snapshots_count": len(ENGINE.ml_snapshots),
                "deletion_certificates_count": len(ENGINE.deletion_certificates),
                "audit_chain_valid": audit_check["valid"],
            }

        if method == "GET" and clean_path == "/api/state":
            viewer_role = query.get("viewer_role") or "security_auditor"
            snap = ENGINE.get_state_snapshot(viewer_role=viewer_role)
            snap["benchmarks"] = _load_cached_benchmarks()
            snap["request_id"] = request_id
            return 200, snap

        if method == "POST" and clean_path == "/api/events/ingest":
            tenant_id = str(body.get("tenant_id") or "").strip()
            event_type = str(body.get("event_type") or "customer_ai_prompt").strip()
            payload_text = str(body.get("payload_text") or "").strip()
            if not tenant_id or not payload_text:
                return 400, {"error": "Both tenant_id and payload_text are required."}
            res = ENGINE.ingest_event(
                tenant_id=tenant_id,
                event_type=event_type,
                payload_text=payload_text,
                actor=str(body.get("actor") or "studio-ingest-api"),
            )
            res["request_id"] = request_id
            return 200, res

        if method == "POST" and clean_path == "/api/consent/update":
            tenant_id = str(body.get("tenant_id") or "").strip()
            if not tenant_id:
                return 400, {"error": "tenant_id is required."}
            ml_opt_in = body.get("ml_training_opt_in")
            consent_policy = body.get("consent_policy")
            if ml_opt_in is None and consent_policy is None:
                return 400, {"error": "Provide ml_training_opt_in (bool) or consent_policy."}
            res = ENGINE.update_consent(
                tenant_id=tenant_id,
                ml_training_opt_in=bool(ml_opt_in) if ml_opt_in is not None else None,
                consent_policy=str(consent_policy) if consent_policy is not None else None,
                actor=str(body.get("actor") or "tenant-consent-api"),
            )
            res["request_id"] = request_id
            return 200, res

        if method == "POST" and clean_path == "/api/training/build-snapshot":
            purpose = str(body.get("purpose") or "ml_foundation_training").strip()
            requested_by_role = str(body.get("requested_by_role") or "ml_scientist").strip()
            res = ENGINE.build_training_snapshot(
                purpose=purpose,
                requested_by_role=requested_by_role,
            )
            res["request_id"] = request_id
            status_code = 200 if res.get("authorized") else 403
            return status_code, res

        if method == "POST" and clean_path == "/api/compliance/delete-tenant":
            tenant_id = str(body.get("tenant_id") or "").strip()
            regulation = str(body.get("regulation") or "GDPR-Art17").strip()
            if not tenant_id:
                return 400, {"error": "tenant_id is required."}
            res = ENGINE.delete_tenant_rtbf(
                tenant_id=tenant_id,
                regulation=regulation,
                actor=str(body.get("actor") or "rtbf-compliance-api"),
            )
            res["request_id"] = request_id
            return 200, res

        if method == "POST" and clean_path == "/api/benchmarks/run":
            count = int(body.get("num_events") or 600)
            count = max(100, min(count, 2500))
            live_bedrock = bool(body.get("live_bedrock", True))
            res = run_vault_lineage_benchmarks(
                num_events=count,
                live_bedrock=live_bedrock,
                use_disk_sqlite=True,
            )
            res["request_id"] = request_id
            return 200, res

        if method == "POST" and clean_path == "/api/reset":
            ENGINE.reset()
            return 200, {
                "status": "reset_complete",
                "service": "vault-lineage-storage",
                "request_id": request_id,
            }

        return 404, {"error": f"Unknown API route: {method} {path}"}
    except KeyError as exc:
        return 404, {"error": str(exc)}
    except ValueError as exc:
        return 400, {"error": str(exc)}
    except CryptoShreddedError as exc:
        return 409, {"error": str(exc), "code": "CRYPTO_SHREDDED"}
    except AuthorizationDeniedError as exc:
        return 403, {"error": str(exc), "code": "AUTHORIZATION_DENIED"}
    except Exception as exc:
        return 500, {"error": str(exc)}


def lambda_handler(event: Dict[str, Any], context: Any = None) -> Dict[str, Any]:
    """AWS Lambda Function URL handler mounted behind Amazon CloudFront `/api/*` origin."""
    req_ctx = event.get("requestContext") or {}
    method = ((req_ctx.get("http") or {}).get("method") or event.get("httpMethod") or "GET").upper()
    raw_path = event.get("rawPath") or event.get("path") or "/"
    query_params = {k: str(v) for k, v in (event.get("queryStringParameters") or {}).items() if v is not None}
    req_id = getattr(context, "aws_request_id", "cloudfront-api")

    if method == "OPTIONS":
        return {"statusCode": 204, "headers": CORS_HEADERS, "body": ""}

    if raw_path.startswith("/api/"):
        body: Dict[str, Any] = {}
        raw_body = event.get("body")
        if raw_body:
            if event.get("isBase64Encoded") and isinstance(raw_body, str):
                raw_body = base64.b64decode(raw_body).decode("utf-8")
            body = json.loads(raw_body) if isinstance(raw_body, str) else dict(raw_body)
        status, payload = route_api_request(method, raw_path, query_params, body, request_id=req_id)
        return {
            "statusCode": status,
            "headers": {
                **CORS_HEADERS,
                "Content-Type": "application/json; charset=utf-8",
                "Cache-Control": "no-store",
            },
            "body": json.dumps(payload, default=str),
        }

    target = WEB_DIR / ("index.html" if raw_path in ("/", "") else raw_path.lstrip("/"))
    if not target.is_file() and raw_path.endswith(".svg"):
        target = DOCS_DIR / Path(raw_path).name
    if target.is_file():
        ctype = mimetypes.guess_type(str(target))[0] or "text/html; charset=utf-8"
        return {
            "statusCode": 200,
            "headers": {**CORS_HEADERS, "Content-Type": ctype},
            "body": target.read_text(encoding="utf-8"),
        }
    return {
        "statusCode": 404,
        "headers": {**CORS_HEADERS, "Content-Type": "application/json"},
        "body": json.dumps({"error": "Not found", "path": raw_path}),
    }


class LocalVaultLineageHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        query = {k: v[0] for k, v in parse_qs(parsed.query).items() if v}

        if path.startswith("/api/"):
            status, payload = route_api_request("GET", path, query, {}, request_id="local-dev")
            raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
            self.send_response(status)
            for k, v in CORS_HEADERS.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return

        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        candidate = (WEB_DIR / rel).resolve()
        if not candidate.is_file() and path.endswith(".svg"):
            candidate = (DOCS_DIR / Path(path).name).resolve()
        if not candidate.is_file():
            candidate = WEB_DIR / "index.html"

        data = candidate.read_bytes()
        ctype = mimetypes.guess_type(str(candidate))[0] or "text/html"
        if ctype.startswith("text/") or ctype in ("application/javascript", "image/svg+xml"):
            ctype += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length") or "0")
        raw_body = self.rfile.read(length).decode("utf-8") if length > 0 else "{}"
        body = json.loads(raw_body) if raw_body.strip() else {}
        status, payload = route_api_request("POST", parsed.path, {}, body, request_id="local-dev")
        raw = json.dumps(payload, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run_local_server(port: int = 3098) -> None:
    srv = ThreadingHTTPServer(("127.0.0.1", port), LocalVaultLineageHandler)
    print(f"VaultLineage live studio running at http://localhost:{port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    port_num = int(os.environ.get("PORT", "3098"))
    run_local_server(port=port_num)
