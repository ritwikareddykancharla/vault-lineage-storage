"""Unit tests for VaultLineage Envelope-Encrypted Event Store, Opt-Out Gate & RTBF Engine."""
from __future__ import annotations

import base64
import json
import os
import unittest

from vault_lineage.benchmarks import run_vault_lineage_benchmarks
from vault_lineage.server import ENGINE, lambda_handler, route_api_request
from vault_lineage.storage_engine import (
    AuthorizationDeniedError,
    CryptoShreddedError,
    VaultLineageEngine,
    tokenize_pii,
)


class TestVaultLineageEngine(unittest.TestCase):
    def setUp(self) -> None:
        os.environ["VAULTLINEAGE_OFFLINE_LLM"] = "1"
        self.engine = VaultLineageEngine()

    def tearDown(self) -> None:
        self.engine.close()

    def test_01_envelope_encryption_roundtrip_and_aad_tamper_detection(self) -> None:
        plaintext = "Confidential model prompt for priya.nair@alphabank.io with SSN 123-45-6789"
        envelope = self.engine.keyring.encrypt_payload("tenant-finserve-alpha", "evt-test-1", plaintext)
        self.assertNotEqual(base64.b64decode(envelope["ciphertext_b64"]), plaintext.encode("utf-8"))

        decrypted = self.engine.keyring.decrypt_payload("tenant-finserve-alpha", "evt-test-1", envelope)
        self.assertEqual(decrypted, plaintext)

        # Cross-tenant AAD replay must fail deterministically
        with self.assertRaises(AuthorizationDeniedError):
            self.engine.keyring.decrypt_payload("tenant-saas-orbit", "evt-test-1", envelope)

        # Ciphertext bit-flip must fail AEAD authentication tag verification
        tampered = dict(envelope)
        ct_bytes = bytearray(base64.b64decode(tampered["ciphertext_b64"]))
        ct_bytes[0] ^= 0xFF
        tampered["ciphertext_b64"] = base64.b64encode(bytes(ct_bytes)).decode("ascii")
        with self.assertRaises(AuthorizationDeniedError):
            self.engine.keyring.decrypt_payload("tenant-finserve-alpha", "evt-test-1", tampered)

    def test_02_pii_detection_and_deterministic_vault_tokenization(self) -> None:
        raw = (
            "Escalate ticket for alice@acme.io, SSN 123-45-6789, key AKIAIOSFODNN7EXAMPLE, "
            "card 4532-1111-2222-3333, phone 415-555-0199, IP 198.51.100.7."
        )
        sanitized_a, findings_a = tokenize_pii("tenant-finserve-alpha", raw, b"test-salt")
        sanitized_b, _ = tokenize_pii("tenant-finserve-alpha", raw, b"test-salt")
        sanitized_other_tenant, _ = tokenize_pii("tenant-saas-orbit", raw, b"test-salt")

        self.assertEqual(sanitized_a, sanitized_b)
        self.assertNotEqual(sanitized_a, sanitized_other_tenant)
        for secret in ("alice@acme.io", "123-45-6789", "AKIAIOSFODNN7EXAMPLE", "4532-1111-2222-3333"):
            self.assertNotIn(secret, sanitized_a)
        categories = {f["category"] for f in findings_a}
        self.assertTrue({"EMAIL", "SSN", "AWS_ACCESS_KEY", "CREDIT_CARD", "PHONE", "IP_ADDRESS"}.issubset(categories))

    def test_03_compliant_ml_snapshot_excludes_opted_out_and_zero_retention_tenants(self) -> None:
        res = self.engine.build_training_snapshot(
            purpose="ml_foundation_training",
            requested_by_role="ml_scientist",
        )
        self.assertTrue(res["authorized"])
        self.assertEqual(res["opt_out_leakage_rate"], 0.0)
        snap = res["snapshot"]
        admitted_tenants = {r["tenant_id"] for r in snap["admitted_records"]}
        self.assertIn("tenant-euro-nordic", admitted_tenants)
        self.assertIn("tenant-finserve-alpha", admitted_tenants)
        self.assertNotIn("tenant-health-meridian", admitted_tenants)
        self.assertNotIn("tenant-gov-aegis", admitted_tenants)

        # Ensure raw PII never enters admitted ML training records
        for rec in snap["admitted_records"]:
            self.assertNotIn("lukas.weber@nordicretail.de", rec["pii_scrubbed_text"])
            self.assertNotIn("123-45-6789", rec["pii_scrubbed_text"])
            self.assertNotIn("AKIAIOSFODNN7EXAMPLE", rec["pii_scrubbed_text"])

    def test_04_real_time_consent_opt_out_revokes_future_snapshots_and_streaming_shards(self) -> None:
        upd = self.engine.update_consent(
            tenant_id="tenant-finserve-alpha",
            ml_training_opt_in=False,
        )
        self.assertEqual(upd["consent_policy"], "ANALYTICS_ONLY_OPTOUT_ML")
        self.assertFalse(upd["ml_training_opt_in"])
        self.assertIn("fs-prompt-embeddings-v2", upd["evicted_streaming_shards"])

        # Subsequent ML training snapshot must block tenant-finserve-alpha completely
        snap_ml = self.engine.build_training_snapshot(
            purpose="ml_foundation_training",
            requested_by_role="ml_scientist",
        )["snapshot"]
        admitted_ml = {r["tenant_id"] for r in snap_ml["admitted_records"]}
        self.assertNotIn("tenant-finserve-alpha", admitted_ml)

        # Analytics rollup by analytics_engineer CAN still include ANALYTICS_ONLY_OPTOUT_ML
        snap_ana = self.engine.build_training_snapshot(
            purpose="product_analytics_rollup",
            requested_by_role="analytics_engineer",
        )["snapshot"]
        admitted_ana = {r["tenant_id"] for r in snap_ana["admitted_records"]}
        self.assertIn("tenant-finserve-alpha", admitted_ana)
        self.assertIn("tenant-health-meridian", admitted_ana)
        self.assertNotIn("tenant-gov-aegis", admitted_ana)

    def test_05_purpose_bound_access_gate_blocks_unauthorized_roles(self) -> None:
        # Analytics engineer attempting to build ML foundation training dataset -> DENIED
        denied = self.engine.build_training_snapshot(
            purpose="ml_foundation_training",
            requested_by_role="analytics_engineer",
        )
        self.assertFalse(denied["authorized"])
        self.assertEqual(denied["gate_verdict"], "DENIED_BY_PURPOSE_ACL")

        # External contractor attempting single-event read -> AuthorizationDeniedError
        sample_event_id = self.engine.events[0]["event_id"]
        with self.assertRaises(AuthorizationDeniedError):
            self.engine.authorize_event_read(sample_event_id, viewer_role="external_contractor")

    def test_06_crypto_shred_rtbf_destroys_dek_and_purges_downstream_lineage(self) -> None:
        # Verify tenant-euro-nordic is initially present in baseline ML snapshot & feature shards
        self.assertIn("tenant-euro-nordic", self.engine.ml_snapshots[0]["tenant_contributions"])
        euro_events = [e for e in self.engine.events if e["tenant_id"] == "tenant-euro-nordic"]
        self.assertGreaterEqual(len(euro_events), 2)

        del_res = self.engine.delete_tenant_rtbf(
            tenant_id="tenant-euro-nordic",
            regulation="GDPR-Art17",
        )
        self.assertEqual(del_res["status"], "CRYPTO_SHREDDED_AND_PURGED")
        cert = del_res["certificate"]
        self.assertEqual(cert["downstream_purge_completeness_pct"], 100.0)
        self.assertEqual(cert["residual_records_remaining"], 0)
        self.assertGreaterEqual(len(cert["downstream_ml_snapshots_purged"]), 1)
        self.assertGreaterEqual(len(cert["downstream_feature_shards_purged"]), 1)

        # Attempting to decrypt raw ciphertext directly must now raise CryptoShreddedError
        for ev in euro_events:
            with self.assertRaises(CryptoShreddedError):
                self.engine.keyring.decrypt_payload(
                    "tenant-euro-nordic", ev["event_id"], ev["encrypted_raw_envelope"]
                )

        # Verify 0 records remain across all ML snapshots and feature shards
        for snap in self.engine.ml_snapshots:
            for rec in snap["admitted_records"]:
                self.assertNotEqual(rec["tenant_id"], "tenant-euro-nordic")
        for shard in self.engine.feature_shards.values():
            self.assertNotIn("tenant-euro-nordic", shard["tenant_event_map"])

    def test_07_signed_compliance_certificate_verification_and_tamper_detection(self) -> None:
        del_res = self.engine.delete_tenant_rtbf("tenant-saas-orbit", regulation="CCPA")
        cert = dict(del_res["certificate"])
        sig = cert.pop("signature_sha256")
        cert.pop("signature_algorithm", None)
        cert.pop("bedrock_compliance_audit", None)

        self.assertTrue(self.engine.keyring.verify_certificate_signature(cert, sig))
        cert["events_crypto_shredded"] = 999
        self.assertFalse(self.engine.keyring.verify_certificate_signature(cert, sig))

    def test_08_immutable_sha256_audit_chain_integrity(self) -> None:
        self.engine.ingest_event(
            tenant_id="tenant-finserve-alpha",
            event_type="audit_probe",
            payload_text="Check audit chain continuity for bob@alphabank.io",
        )
        self.engine.update_consent("tenant-finserve-alpha", consent_policy="STRICT_ZERO_RETENTION")
        check = self.engine.verify_audit_chain()
        self.assertTrue(check["valid"])
        self.assertGreaterEqual(check["entries_checked"], 10)

        # Simulate ledger tampering and verify detection
        self.engine.audit_log[3].status = "TAMPERED_STATUS"
        broken = self.engine.verify_audit_chain()
        self.assertFalse(broken["valid"])
        self.assertEqual(broken["broken_at_seq"], 4)

    def test_09_api_router_and_lambda_handler_full_lifecycle(self) -> None:
        ENGINE.reset()
        code, health = route_api_request("GET", "/api/health", {}, {})
        self.assertEqual(code, 200)
        self.assertEqual(health["service"], "vault-lineage-storage")
        self.assertEqual(health["bedrock_model"], "us.amazon.nova-lite-v1:0")

        code, ingest = route_api_request(
            "POST",
            "/api/events/ingest",
            {},
            {
                "tenant_id": "tenant-euro-nordic",
                "event_type": "support_chat",
                "payload_text": "Verify EU invoice for eva.muller@nordicretail.de",
            },
        )
        self.assertEqual(code, 200)
        self.assertGreaterEqual(ingest["event"]["pii_tokens_count"], 1)

        code, consent = route_api_request(
            "POST",
            "/api/consent/update",
            {},
            {"tenant_id": "tenant-saas-orbit", "ml_training_opt_in": False},
        )
        self.assertEqual(code, 200)
        self.assertFalse(consent["ml_training_opt_in"])

        # Lambda Function URL event test for /api/training/build-snapshot
        lam_resp = lambda_handler(
            {
                "rawPath": "/api/training/build-snapshot",
                "requestContext": {"http": {"method": "POST"}},
                "body": json.dumps({"purpose": "ml_foundation_training", "requested_by_role": "ml_scientist"}),
            }
        )
        self.assertEqual(lam_resp["statusCode"], 200)
        snap_payload = json.loads(lam_resp["body"])
        self.assertEqual(snap_payload["opt_out_leakage_rate"], 0.0)

        # Delete tenant via /api/compliance/delete-tenant
        code, del_payload = route_api_request(
            "POST",
            "/api/compliance/delete-tenant",
            {},
            {"tenant_id": "tenant-euro-nordic", "regulation": "GDPR-Art17"},
        )
        self.assertEqual(code, 200)
        self.assertEqual(del_payload["status"], "CRYPTO_SHREDDED_AND_PURGED")
        self.assertIn("memo", del_payload["bedrock_compliance_audit"])

        ENGINE.reset()

    def test_10_sqlite_event_opt_out_and_rtbf_benchmark_invariants(self) -> None:
        bench = run_vault_lineage_benchmarks(num_events=400, live_bedrock=False, use_disk_sqlite=True)
        self.assertEqual(bench["events_benchmarked"], 400)
        self.assertEqual(bench["opt_out_leakage_rate_pct"], 0.0)
        self.assertEqual(bench["raw_pii_leakage_count"], 0)
        self.assertEqual(bench["crypto_shred_undecipherable_pct"], 100.0)
        self.assertEqual(bench["downstream_lineage_purge_pct"], 100.0)
        self.assertTrue(bench["audit_chain_verified"])


if __name__ == "__main__":
    unittest.main()
