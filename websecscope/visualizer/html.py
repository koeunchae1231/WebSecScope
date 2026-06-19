def score_class(score: int) -> str:
    if score >= 80:
        return "good"
    if score >= 60:
        return "warn"
    return "bad"


def status_class(status: str) -> str:
    status = status.lower()
    if status == "pass":
        return "pass"
    if status == "fail":
        return "fail"
    return "warning"
