from websecscope.models import RISK_HIGH, RISK_LOW, RISK_MEDIUM

SECURITY_HEADERS = {
    "strict-transport-security": ("Strict-Transport-Security", RISK_HIGH),
    "content-security-policy": ("Content-Security-Policy", RISK_HIGH),
    "x-content-type-options": ("X-Content-Type-Options", RISK_MEDIUM),
    "x-frame-options": ("X-Frame-Options", RISK_MEDIUM),
    "referrer-policy": ("Referrer-Policy", RISK_LOW),
    "permissions-policy": ("Permissions-Policy", RISK_LOW),
}
