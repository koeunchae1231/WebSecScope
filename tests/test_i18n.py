from websecscope.i18n import localize_finding, normalize_language, severity_label


def test_normalize_language_defaults_to_ko():
    assert normalize_language(None) == "ko"
    assert normalize_language("unsupported") == "ko"


def test_severity_label_supports_korean_and_english():
    assert severity_label("high", "en") == "High"
    assert severity_label("high", "ko") == "높음"


def test_localize_finding_adds_korean_security_header_text():
    payload = {
        "id": "WEB_HEADER_CONTENT_SECURITY_POLICY",
        "check_id": "WEB_HEADER_CONTENT_SECURITY_POLICY",
        "title": "Content-Security-Policy header",
        "description": "original",
        "recommendation": "No action required.",
        "severity": "high",
    }

    localized = localize_finding(payload, "ko")

    assert localized["title"] == "Content-Security-Policy 헤더"
    assert localized["severity_label"] == "높음"
