from websecscope.models import FAIL, PASS, WARNING, RISK_HIGH, RISK_INFO, RISK_LOW
from websecscope.scanner import web


def test_sensitive_path_observation_records_redirect_location():
    observation = web._sensitive_path_observation(
        "admin",
        {"status": 302, "location": "/login"},
    )

    assert "HTTP 302" in observation
    assert "location=/login" in observation


def test_sensitive_path_interpretation_separates_protected_status():
    interpretation = web._sensitive_path_interpretation({403})

    assert "protected" in interpretation
    assert "not a confirmed exposure" in interpretation


def test_sensitive_path_200_is_exposed(monkeypatch):
    monkeypatch.setattr(web, "SENSITIVE_PATHS", ["admin"])
    monkeypatch.setattr(
        web,
        "_request",
        lambda url, method="HEAD", follow_redirects=True: {
            "status": 200,
            "headers": {},
            "location": None,
            "error": None,
        },
    )

    finding = web._scan_sensitive_paths("https://example.com")[0]

    assert finding.status == FAIL
    assert finding.risk == RISK_HIGH
    assert "exposed" in finding.evidence


def test_sensitive_path_403_is_review_not_failure(monkeypatch):
    monkeypatch.setattr(web, "SENSITIVE_PATHS", ["admin"])
    monkeypatch.setattr(
        web,
        "_request",
        lambda url, method="HEAD", follow_redirects=True: {
            "status": 403,
            "headers": {},
            "location": None,
            "error": None,
        },
    )

    finding = web._scan_sensitive_paths("https://example.com")[0]

    assert finding.status == WARNING
    assert finding.risk == RISK_LOW
    assert "protected but exists" in finding.evidence


def test_sensitive_path_404_is_pass(monkeypatch):
    monkeypatch.setattr(web, "SENSITIVE_PATHS", ["admin"])
    monkeypatch.setattr(
        web,
        "_request",
        lambda url, method="HEAD", follow_redirects=True: {
            "status": 404,
            "headers": {},
            "location": None,
            "error": None,
        },
    )

    finding = web._scan_sensitive_paths("https://example.com")[0]

    assert finding.status == PASS
    assert finding.risk == RISK_INFO
