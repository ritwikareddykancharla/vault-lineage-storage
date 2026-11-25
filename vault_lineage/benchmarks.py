"""Real SQLite + KMS Envelope + Live Amazon Bedrock (`us.amazon.nova-lite-v1:0`) Benchmark Suite."""
from __future__ import annotations

import json
import os
import statistics
import tempfile
import time
from typing import Any, Dict, List

from .storage_engine import (
    AuthorizationDeniedError,
    CryptoShreddedError,
    VaultLineageEngine,
)


def run_vault_lineage_benchmarks(
    num_events: int = 1200,
    live_bedrock: bool = False,
    use_disk_sqlite: bool = True,
) -> Dict[str, Any]:
    """Executes real SQLite event ingestion, opt-out snapshot filtering, auth gates, RTBF purge, and Bedrock audits."""
    prev_offline = os.environ.get("VAULTLINEAGE_OFFLINE_LLM")
    if live_bedrock:
        os.environ.pop("VAULTLINEAGE_OFFLINE_LLM", None)
    else:
        os.environ["VAULTLINEAGE_OFFLINE_LLM"] = "1"

    tmp_db = os.path.join(tempfile.gettempdir(), f"vaultlineage_bench_{os.getpid()}.sqlite") if use_disk_sqlite else ":memory:"
    try:
        engine = VaultLineageEngine(db_path=tmp_db, seed_initial=False)

        # Provision 20 enterprise tenants:
        #   - 10 ALLOW_ML_TRAINING (50%)
        #   - 6 ANALYTICS_ONLY_OPTOUT_ML (30%)
        #   - 4 STRICT_ZERO_RETENTION (20%)
        tenant_specs = []
        for idx in range(20):
            if idx < 10:
                policy = "ALLOW_ML_TRAINING"
            elif idx < 16:
                policy = "ANALYTICS_ONLY_OPTOUT_ML"
            else:
                policy = "STRICT_ZERO_RETENTION"
            tid = f"tenant-bench-{idx:02d}"
            region = "eu-central-1" if idx % 3 == 0 else "us-west-2"
            engine.register_or_ensure_tenant(
                tenant_id=tid,
                name=f"Benchmark Enterprise {idx:02d}",
                region=region,
                consent_policy=policy,
            )
            tenant_specs.append((tid, policy))

        sample_payloads = [
            "Customer escalation from user{i}@enterprise.io (SSN 123-45-6789) regarding multi-region KMS rotation.",
            "Agent trace {i}: rotated staging key AKIAIOSFODNN7EXAMPLE and patched billing contact +1 415-555-0199.",
            "RAG retrieval query {i}: summarize quarterly cloud margin covenant without exposing card 4532-1100-9988-7766.",
            "Code synthesis {i}: implement backpressure token bucket for client IP 203.0.113.42 in Python 3.12.",
        ]

        ingest_latencies_ms: List[float] = []
        total_pii_tokenized = 0
        t_ingest_wall_start = time.perf_counter()
        for i in range(num_events):
            tid, _ = tenant_specs[i % 20]
            payload = sample_payloads[i % len(sample_payloads)].format(i=i)
            t_ev = time.perf_counter()
            res = engine.ingest_event(
                tenant_id=tid,
                event_type="benchmark_ai_event",
                payload_text=payload,
                actor="bench-ingest",
                serialize_view=False,
            )
            ingest_latencies_ms.append((time.perf_counter() - t_ev) * 1000.0)
            total_pii_tokenized += int(res["event"]["pii_tokens_count"])
        ingest_wall_s = time.perf_counter() - t_ingest_wall_start

        sorted_ing = sorted(ingest_latencies_ms)
        events_per_sec = round(num_events / max(ingest_wall_s, 1e-6), 1)
        mean_ingest_ms = round(statistics.mean(sorted_ing), 3)
        p50_ingest_ms = round(statistics.median(sorted_ing), 3)
        p95_ingest_ms = round(sorted_ing[min(len(sorted_ing) - 1, int(len(sorted_ing) * 0.95))], 3)

        # 2. Build ML Foundation Training Snapshot via SQLite JOIN + Opt-Out Gate
        t_snap_start = time.perf_counter()
        snap_res = engine.build_training_snapshot(
            purpose="ml_foundation_training",
            requested_by_role="ml_scientist",
        )
        snap_ms = round((time.perf_counter() - t_snap_start) * 1000.0, 2)
        snapshot = snap_res["snapshot"]
        admitted_before_rtbf = snapshot["admitted_count"]
        blocked_optout_count = snapshot["blocked_count"]
        pii_quarantined_in_snap = snapshot["pii_spans_quarantined"]

        opted_out_tenants = {tid for tid, pol in tenant_specs if pol != "ALLOW_ML_TRAINING"}
        leaked_records = [
            r for r in snapshot["admitted_records"] if r["tenant_id"] in opted_out_tenants
        ]
        raw_pii_leaks = [
            r
            for r in snapshot["admitted_records"]
            if ("123-45-6789" in r["pii_scrubbed_text"])
            or ("AKIAIOSFODNN7EXAMPLE" in r["pii_scrubbed_text"])
            or ("@enterprise.io" in r["pii_scrubbed_text"])
            or ("4532-1100-9988-7766" in r["pii_scrubbed_text"])
        ]

        # 3. Purpose-bound SQLite authorization latency across 300 mixed role probes
        auth_latencies_ms: List[float] = []
        unauthorized_blocks = 0
        unauthorized_probes = 0
        probe_events = engine.events[: min(300, len(engine.events))]
        for idx, ev in enumerate(probe_events):
            role = ("ml_scientist", "analytics_engineer", "external_contractor")[idx % 3]
            purpose = "ml_foundation_training" if role != "analytics_engineer" else "product_analytics_rollup"
            is_expected_deny = (
                role == "external_contractor"
                or (
                    purpose == "ml_foundation_training"
                    and engine.tenants[ev["tenant_id"]]["consent_policy"] != "ALLOW_ML_TRAINING"
                )
                or (
                    purpose == "product_analytics_rollup"
                    and engine.tenants[ev["tenant_id"]]["consent_policy"] == "STRICT_ZERO_RETENTION"
                )
            )
            if is_expected_deny:
                unauthorized_probes += 1
            t0 = time.perf_counter()
            try:
                engine.authorize_event_read(ev["event_id"], viewer_role=role, purpose=purpose)
            except AuthorizationDeniedError:
                unauthorized_blocks += 1
            auth_latencies_ms.append((time.perf_counter() - t0) * 1000.0)

        sorted_auth = sorted(auth_latencies_ms)
        p50_auth_ms = round(statistics.median(sorted_auth), 3)
        p95_auth_ms = round(sorted_auth[min(len(sorted_auth) - 1, int(len(sorted_auth) * 0.95))], 3)
        mean_auth_ms = round(statistics.mean(sorted_auth), 3)

        # 4. Execute RTBF Crypto-Shredding + SQLite Downstream Lineage Purge + Bedrock Nova Audits
        rtbf_tenants = [
            ("tenant-bench-00", "GDPR-Art17"),
            ("tenant-bench-01", "CCPA"),
            ("tenant-bench-02", "GDPR-Art17"),
        ]
        crypto_purge_latencies_ms: List[float] = []
        bedrock_latencies_ms: List[float] = []
        bedrock_tokens_total = 0
        bedrock_mode_observed = "deterministic-auditor-fallback"
        sample_bedrock_memo = ""

        for tid, reg in rtbf_tenants:
            del_out = engine.delete_tenant_rtbf(tenant_id=tid, regulation=reg)
            cert = del_out["certificate"]
            b_audit = del_out["bedrock_compliance_audit"]
            crypto_purge_latencies_ms.append(float(cert["sla_elapsed_ms"]))
            bedrock_latencies_ms.append(float(b_audit["latency_ms"]))
            bedrock_tokens_total += int(b_audit.get("total_tokens") or 0)
            bedrock_mode_observed = str(b_audit.get("invocation_mode") or bedrock_mode_observed)
            if not sample_bedrock_memo:
                sample_bedrock_memo = str(b_audit.get("memo") or "")

        shredded_ids = {t for t, _ in rtbf_tenants}
        shredded_ciphertexts_tested = 0
        shredded_ciphertexts_blocked = 0
        for ev in engine.events:
            if ev["tenant_id"] in shredded_ids:
                shredded_ciphertexts_tested += 1
                try:
                    engine.keyring.decrypt_payload(ev["tenant_id"], ev["event_id"], ev["encrypted_raw_envelope"])
                except CryptoShreddedError:
                    shredded_ciphertexts_blocked += 1

        residual_downstream = sum(
            sum(1 for r in s["admitted_records"] if r["tenant_id"] in shredded_ids)
            for s in engine.ml_snapshots
        ) + sum(
            sum(len(s["tenant_event_map"].get(tid, [])) for tid in shredded_ids)
            for s in engine.feature_shards.values()
        )

        audit_check = engine.verify_audit_chain()
        engine.close()

        return {
            "benchmark_suite": "VaultLineage v1.0 SQLite + KMS Envelope + Bedrock Nova Suite",
            "storage_engine": "SQLite WAL + KMS-AEAD-256 (SHA256-CTR + HMAC-SHA256)",
            "events_benchmarked": num_events,
            "tenants_benchmarked": 20,
            "pii_spans_tokenized_total": total_pii_tokenized,
            "ingest_throughput_events_per_sec": events_per_sec,
            "mean_envelope_ingest_ms": mean_ingest_ms,
            "p50_envelope_ingest_ms": p50_ingest_ms,
            "p95_envelope_ingest_ms": p95_ingest_ms,
            "ml_snapshot_build_ms": snap_ms,
            "ml_snapshot_admitted_events": admitted_before_rtbf,
            "ml_snapshot_blocked_optout_events": blocked_optout_count,
            "pii_spans_quarantined_in_snapshot": pii_quarantined_in_snap,
            "opt_out_leakage_count": len(leaked_records),
            "opt_out_leakage_rate_pct": 0.0 if len(leaked_records) == 0 else round((len(leaked_records) / max(admitted_before_rtbf, 1)) * 100.0, 4),
            "raw_pii_leakage_count": len(raw_pii_leaks),
            "purpose_auth_probes": len(probe_events),
            "purpose_auth_p50_ms": p50_auth_ms,
            "purpose_auth_p95_ms": p95_auth_ms,
            "purpose_auth_mean_ms": mean_auth_ms,
            "unauthorized_probes_count": unauthorized_probes,
            "unauthorized_blocks_count": unauthorized_blocks,
            "unauthorized_access_block_rate_pct": round(
                (unauthorized_blocks / max(unauthorized_probes, 1)) * 100.0, 2
            ),
            "rtbf_tenants_shredded": len(rtbf_tenants),
            "shredded_ciphertexts_tested": shredded_ciphertexts_tested,
            "shredded_ciphertexts_blocked": shredded_ciphertexts_blocked,
            "crypto_shred_sql_purge_mean_ms": round(statistics.mean(crypto_purge_latencies_ms), 3),
            "crypto_shred_undecipherable_pct": round(
                (shredded_ciphertexts_blocked / max(shredded_ciphertexts_tested, 1)) * 100.0, 2
            ),
            "downstream_lineage_purge_pct": 100.0 if residual_downstream == 0 else 0.0,
            "residual_deleted_records": residual_downstream,
            "bedrock_model": os.environ.get("VAULTLINEAGE_BEDROCK_MODEL", "us.amazon.nova-lite-v1:0"),
            "bedrock_invocation_mode": bedrock_mode_observed,
            "bedrock_audit_calls": len(rtbf_tenants),
            "bedrock_audit_p50_ms": round(statistics.median(bedrock_latencies_ms), 2),
            "bedrock_audit_mean_ms": round(statistics.mean(bedrock_latencies_ms), 2),
            "bedrock_total_tokens": bedrock_tokens_total,
            "sample_bedrock_memo": sample_bedrock_memo,
            "audit_chain_verified": audit_check["valid"],
            "audit_entries_verified": audit_check["entries_checked"],
        }
    finally:
        if use_disk_sqlite:
            for suffix in ("", "-wal", "-shm"):
                p = tmp_db + suffix
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except OSError:
                        pass
        if prev_offline is None:
            os.environ.pop("VAULTLINEAGE_OFFLINE_LLM", None)
        else:
            os.environ["VAULTLINEAGE_OFFLINE_LLM"] = prev_offline


if __name__ == "__main__":
    results = run_vault_lineage_benchmarks(num_events=1200, live_bedrock=True, use_disk_sqlite=True)
    print(json.dumps(results, indent=2))
