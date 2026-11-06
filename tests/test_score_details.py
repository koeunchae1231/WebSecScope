import json

import pytest

from websecscope.models import Finding, ScanResult
from websecscope.scoring import calculate_score, calculate_score_details


def finding(status="FAIL", risk="HIGH", evidence="observed", title="Same title", metadata=None, check_id="TEST"):
    return Finding(check_id, "web", title, status, risk, evidence, "Review", metadata or {})


@pytest.mark.parametrize("status,expected", [("FAIL", 85), ("WARNING", 93), ("PASS", 100)])
@pytest.mark.parametrize("text", ["not skipped", "a skipped step was mentioned", "unskipped"])
def test_free_text_does_not_skip_scoring(status, expected, text):
    f = finding(status=status, evidence=text, title=text, check_id=text)
    result = calculate_score_details([f])
    assert result["score"] == expected
    assert result["entries"][0]["skipped"] is False


@pytest.mark.parametrize("status", ["PASS", "WARNING", "FAIL"])
def test_explicit_skip_has_precedence_and_does_not_consume_duplicate(status):
    result = calculate_score_details([finding(status=status, metadata={"skipped": True}), finding()])
    assert result["score"] == 85
    assert result["entries"][0]["exclusion_reason"] == "metadata.skipped"
    assert result["entries"][0]["duplicate_multiplier"] is None
    assert result["entries"][1]["duplicate_multiplier"] == 1


@pytest.mark.parametrize("value", [False, "true", 1, None])
def test_only_boolean_true_is_explicit_skip(value):
    assert calculate_score([finding(metadata={"skipped": value})]) == 85


@pytest.mark.parametrize("check_id", ["LINUX_SCAN_SKIPPED", "DOCKER_SCAN_SKIPPED"])
def test_exact_legacy_execution_ids_are_supported(check_id):
    result = calculate_score_details([finding(check_id=check_id)])
    assert result["score"] == 100
    assert result["entries"][0]["exclusion_reason"] == "legacy_skipped_check_id"
    assert calculate_score([finding(check_id=check_id + "_OTHER")]) == 85


def test_auth_404_uncertainty_still_penalized():
    result = calculate_score_details([finding(status="WARNING", risk="LOW", metadata={
        "authentication_assessed": False, "reason_code": "NOT_FOUND_AUTH_UNASSESSED"})])
    assert result["score"] == 99
    assert result["entries"][0]["final_penalty"] == 1


def test_approved_order_invariance_and_warning_floor():
    assert calculate_score([finding(status="PASS"), finding()]) == 85
    assert calculate_score([finding(), finding(status="PASS")]) == 85
    result = calculate_score_details([finding(status="WARNING", risk="LOW") for _ in range(7)])
    assert result["score"] == 93
    assert [r["computed_penalty"] for r in result["entries"]] == [1]*7
    assert [r["duplicate_multiplier"] for r in result["entries"]] == [1]+[.35]*6
    from websecscope.analyzer.cve import build_cve_findings
    cves = build_cve_findings({"items": [
        {"cve_id": "CVE-SYNTHETIC", "cvss_score": 8.0, "confidence": confidence}
        for confidence in ("high", "medium")
    ]})
    # Their evidence differs; without asset scope B does not infer equivalence.
    assert calculate_score(cves) == 81
    assert calculate_score(cves[::-1]) == 81


def test_rounding_confidence_cvss_and_zero_weight():
    result = calculate_score_details([
        finding(status="WARNING", metadata={"confidence": "medium"}),
        finding(metadata={"confidence": "low"}),
        finding(risk="INFO", title="info"),
    ])
    assert [r["computed_penalty"] for r in result["entries"]] == [7, 1, 0]
    assert next(r for r in result["entries"] if r["status"] == "WARNING")["status_base_penalty"] == 7
    cve = finding(risk="LOW", metadata={"cvss_score": 3.0})
    cve.category = "cve"
    assert calculate_score_details([cve])["entries"][0]["confidence_multiplier"] == .6
    cve.metadata["confidence"] = "low"
    assert calculate_score_details([cve])["entries"][0]["confidence_multiplier"] == .5


def test_clamp_ledger_and_identifiers_reconcile():
    fs = [finding(risk="CRITICAL", title=f"issue {i}", check_id=f"TEST_{i}") for i in range(6)]
    result = calculate_score_details(fs)
    assert result["score"] == 0
    assert result["unclamped_score"] == -50
    assert result["total_computed_penalty"] == 150
    assert result["clamp_adjustment"] == 50
    assert sum(r["clamp_reduction"] for r in result["entries"]) == 50
    assert sum(r["final_penalty"] for r in result["entries"]) == result["total_final_penalty"] == 100
    assert 100-result["total_final_penalty"] == result["score"]
    assert len({r["finding_id"] for r in result["entries"]}) == len(fs)
    assert calculate_score_details([])["score"] == 100


def test_orchestrator_records_same_calculation_and_json(monkeypatch, tmp_path):
    from websecscope.scanner import orchestrator
    from websecscope.reporter.json import write_json_report

    fs = [finding(evidence="not skipped")]
    monkeypatch.setattr(orchestrator, "scan_web_target", lambda target: fs)
    result = orchestrator.run_scan("http://unused.invalid", include_api_auth=False,
        include_linux=False, include_docker=False, include_service_detect=False, include_cve=False)
    assert result.score == result.score_details["score"] == 85
    assert result.to_dict("ko")["score_details"] == result.to_dict("en")["score_details"]
    path = write_json_report(result, tmp_path/"report.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["score_details"]["total_final_penalty"] == 15
    assert payload["score"] == 100-sum(e["final_penalty"] for e in payload["score_details"]["entries"])
    # Existing manually constructed ScanResult remains valid; no fabricated ledger.
    assert ScanResult(target="legacy", findings=fs, score=85).to_dict()["score_details"] == {}
