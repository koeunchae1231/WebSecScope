from websecscope.analyzer.score import calculate_score, grade_for_score
from websecscope.models import FAIL, WARNING, Finding, RISK_HIGH, RISK_MEDIUM


def test_calculate_score_penalizes_high_failure():
    finding = Finding(
        check_id="TEST_HIGH",
        category="web",
        title="High risk finding",
        status=FAIL,
        risk=RISK_HIGH,
        evidence="evidence",
        recommendation="fix",
    )

    assert calculate_score([finding]) == 85


def test_calculate_score_uses_lower_warning_penalty():
    finding = Finding(
        check_id="TEST_MEDIUM",
        category="web",
        title="Medium review finding",
        status=WARNING,
        risk=RISK_MEDIUM,
        evidence="evidence",
        recommendation="fix",
    )

    assert calculate_score([finding]) == 96


def test_grade_for_score_boundaries():
    assert grade_for_score(90) == "A"
    assert grade_for_score(80) == "B"
    assert grade_for_score(70) == "C"
    assert grade_for_score(60) == "D"
    assert grade_for_score(59) == "F"
