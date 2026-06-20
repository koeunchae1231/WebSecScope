from websecscope.owasp import owasp_category_for


def test_owasp_maps_csp_to_security_misconfiguration():
    assert (
        owasp_category_for("WEB_HEADER_CONTENT_SECURITY_POLICY", "web")
        == "A05 Security Misconfiguration"
    )


def test_owasp_maps_auth_to_a07():
    assert (
        owasp_category_for("AUTH_MAY_BE_MISSING_ADMIN", "auth")
        == "A07 Identification and Authentication Failures"
    )


def test_owasp_maps_cve_to_a06():
    assert (
        owasp_category_for("CVE_CVE_2026_0001", "cve")
        == "A06 Vulnerable and Outdated Components"
    )
