from __future__ import annotations

import json
import os
import queue
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from websecscope.guide import recommendation_for
from websecscope.models import FAIL, PASS, WARNING, Finding, RISK_CRITICAL, RISK_HIGH, RISK_INFO, RISK_LOW, RISK_MEDIUM, build_finding

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_PATH = Path(".websecscope_cache/cve_cache.json")
REQUEST_DEADLINE_SECONDS = 4
REQUEST_DELAY_SECONDS = 0.6
MAX_RESULTS_PER_QUERY = 10
SERVICE_PATTERN = re.compile(r"\b([a-zA-Z][a-zA-Z0-9_.-]+)[ /:-](\d+(?:\.\d+){1,3})\b")


def analyze_cves(
    findings: list[Finding],
    service_inventory: list[dict[str, Any]] | None = None,
    enabled: bool = True,
) -> tuple[dict[str, Any], list[Finding]]:
    inventory = service_inventory or []
    candidates = _build_candidates(findings, inventory)
    if not enabled:
        lookup = {
            "enabled": False,
            "reason": "CVE lookup skipped by CLI option.",
            "queries": [],
            "items": [],
            "errors": [],
        }
        return lookup, [_inventory_finding(candidates, "CVE lookup skipped by CLI option.")]

    lookup = lookup_cves(candidates, inventory)
    cve_findings = build_cve_findings(lookup)
    if not cve_findings:
        cve_findings = [_inventory_finding(candidates, _lookup_evidence(lookup))]
    return lookup, cve_findings


def lookup_cves(candidates: list[dict[str, str]], service_inventory: list[dict[str, Any]]) -> dict[str, Any]:
    cache = _load_cache()
    queries = []
    items = []
    errors = []
    seen_keys: set[str] = set()

    for candidate in candidates:
        product = candidate.get("product", "unknown")
        version = candidate.get("version", "unknown")
        key = _cache_key(product, version)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        if product == "unknown" or version == "unknown":
            queries.append(_query_record(product, version, "skipped", "CVE lookup skipped: product/version unknown"))
            continue

        if key in cache:
            cached_items = cache[key].get("items", [])
            cached_error = cache[key].get("response_summary", {}).get("error")
            if cached_error:
                message = f"Cached NVD lookup failure for {product} {version}: {cached_error}"
                queries.append(_query_record(product, version, "cached_error", message))
                errors.append(message)
            else:
                queries.append(_query_record(product, version, "cache_hit", f"Loaded {len(cached_items)} cached CVE item(s)."))
            items.extend(cached_items)
            continue

        payload, error = _query_nvd(product, version)
        if error:
            message = f"NVD lookup failed for {product} {version}: {error}"
            queries.append(_query_record(product, version, "error", message))
            errors.append(message)
            cache[key] = _cache_entry(product, version, [], message)
            _save_cache(cache)
            time.sleep(REQUEST_DELAY_SECONDS)
            continue

        normalized = normalize_nvd_response(payload, product, version)
        queries.append(_query_record(product, version, "fetched", f"Fetched {len(normalized)} potentially related CVE item(s)."))
        items.extend(normalized)
        cache[key] = _cache_entry(product, version, normalized, None)
        _save_cache(cache)
        time.sleep(REQUEST_DELAY_SECONDS)

    skipped_inventory = [
        item for item in service_inventory if _item_product_version(item) == ("unknown", "unknown")
    ]
    for item in skipped_inventory:
        queries.append(
            _query_record(
                item.get("detected_product", "unknown"),
                item.get("version", "unknown"),
                "skipped",
                "CVE lookup skipped: product/version unknown",
            )
        )

    return {
        "enabled": True,
        "api": "NVD CVE API 2.0",
        "cache_path": str(CACHE_PATH),
        "queries": queries,
        "items": items,
        "errors": errors,
        "note": "CVE matches are automated reference data and are not a confirmed vulnerability finding without human verification.",
    }


def normalize_nvd_response(payload: dict[str, Any], product: str, version: str) -> list[dict[str, Any]]:
    results = []
    for vulnerability in payload.get("vulnerabilities", [])[:MAX_RESULTS_PER_QUERY]:
        cve = vulnerability.get("cve", {})
        descriptions = cve.get("descriptions", [])
        description = _english_description(descriptions)
        metrics = cve.get("metrics", {})
        cvss = _select_cvss(metrics)
        references = [
            reference.get("url")
            for reference in cve.get("references", {}).get("referenceData", [])
            if reference.get("url")
        ][:5]
        confidence = _confidence_for(cve, description, product, version)
        results.append(
            {
                "cve_id": cve.get("id", "unknown"),
                "source": cve.get("sourceIdentifier", "NVD"),
                "published": cve.get("published", ""),
                "last_modified": cve.get("lastModified", ""),
                "cvss_version": cvss["version"],
                "cvss_score": cvss["score"],
                "severity": cvss["severity"],
                "description": description,
                "references": references,
                "matched_product": product,
                "matched_version": version,
                "confidence": confidence,
                "evidence": _cve_evidence(cve, description, product, version, confidence),
            }
        )
    return results


def build_cve_findings(lookup: dict[str, Any]) -> list[Finding]:
    findings = []
    for item in lookup.get("items", []):
        risk = _risk_from_cvss(item.get("cvss_score"))
        confidence = item.get("confidence", "low")
        findings.append(
            build_finding(
                f"CVE_{item.get('cve_id', 'UNKNOWN')}",
                "cve",
                f"Potentially related CVE: {item.get('cve_id', 'unknown')}",
                FAIL if confidence == "high" and risk in {RISK_HIGH, RISK_CRITICAL} else WARNING,
                risk,
                (
                    f"{item.get('matched_product')} {item.get('matched_version')}; "
                    f"CVSS={item.get('cvss_score')} ({item.get('cvss_version')}); "
                    f"confidence={confidence}; {item.get('evidence')}"
                ),
                recommendation_for("CVE_REVIEW"),
                description="NVD returned a potentially related CVE for the detected product/version. Confirm applicability before treating it as exploitable.",
                metadata={
                    "confidence": confidence,
                    "cvss_score": item.get("cvss_score"),
                    "cve": item,
                },
            )
        )
    return findings


def _build_candidates(findings: list[Finding], service_inventory: list[dict[str, Any]]) -> list[dict[str, str]]:
    candidates: dict[str, dict[str, str]] = {}
    for product, version in _extract_services(findings):
        candidates[_cache_key(product, version)] = {"product": product, "version": version, "source": "finding_evidence"}
    for product, version in _extract_inventory_services(service_inventory):
        candidates[_cache_key(product, version)] = {"product": product, "version": version, "source": "service_inventory"}
    return sorted(candidates.values(), key=lambda item: (item["product"], item["version"]))


def _extract_services(findings: list[Finding]) -> list[tuple[str, str]]:
    services: set[tuple[str, str]] = set()
    for finding in findings:
        for name, version in SERVICE_PATTERN.findall(finding.evidence):
            if name.lower() not in {"http", "https", "returned", "port", "protocol", "version"}:
                services.add((name, version))
    return sorted(services)


def _extract_inventory_services(service_inventory: list[dict[str, Any]]) -> list[tuple[str, str]]:
    services = []
    for item in service_inventory:
        product, version = _item_product_version(item)
        if product != "unknown" and version != "unknown":
            services.append((product, version))
    return services


def _item_product_version(item: dict[str, Any]) -> tuple[str, str]:
    normalized = item.get("normalized_service", {})
    product = normalized.get("product") or item.get("detected_product") or "unknown"
    version = normalized.get("version") or item.get("version") or "unknown"
    return product, version


def _query_nvd(product: str, version: str) -> tuple[dict[str, Any] | None, str | None]:
    params = urlencode({"keywordSearch": f"{product} {version}", "resultsPerPage": str(MAX_RESULTS_PER_QUERY)})
    url = f"{NVD_API_URL}?{params}"
    headers = {"User-Agent": "WebSecScope/1.0"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    results: queue.Queue[tuple[dict[str, Any] | None, str | None]] = queue.Queue(maxsize=1)
    worker = threading.Thread(target=_query_nvd_direct, args=(url, headers, results), daemon=True)
    worker.start()
    try:
        return results.get(timeout=REQUEST_DEADLINE_SECONDS)
    except queue.Empty:
        return None, "request deadline exceeded"


def _query_nvd_direct(
    url: str,
    headers: dict[str, str],
    results: queue.Queue[tuple[dict[str, Any] | None, str | None]],
) -> None:
    request = Request(url, headers=headers)
    try:
        with urlopen(request, timeout=REQUEST_DEADLINE_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
            results.put((payload, None))
    except Exception as exc:
        results.put((None, f"{type(exc).__name__}: request failed"))


def _select_cvss(metrics: dict[str, Any]) -> dict[str, Any]:
    for metric_key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")):
        values = metrics.get(metric_key) or []
        if not values:
            continue
        data = values[0].get("cvssData", {})
        score = data.get("baseScore")
        severity = values[0].get("baseSeverity") or data.get("baseSeverity") or _severity_from_score(score)
        return {"version": version, "score": score if score is not None else "unknown", "severity": severity or "unknown"}
    return {"version": "unknown", "score": "unknown", "severity": "unknown"}


def _risk_from_cvss(score: Any) -> str:
    if not isinstance(score, (int, float)):
        return RISK_INFO
    if score >= 9.0:
        return RISK_CRITICAL
    if score >= 7.0:
        return RISK_HIGH
    if score >= 4.0:
        return RISK_MEDIUM
    if score >= 0.1:
        return RISK_LOW
    return RISK_INFO


def _severity_from_score(score: Any) -> str:
    risk = _risk_from_cvss(score)
    return {
        RISK_CRITICAL: "CRITICAL",
        RISK_HIGH: "HIGH",
        RISK_MEDIUM: "MEDIUM",
        RISK_LOW: "LOW",
        RISK_INFO: "UNKNOWN",
    }[risk]


def _confidence_for(cve: dict[str, Any], description: str, product: str, version: str) -> str:
    haystack = f"{description} {json.dumps(cve.get('configurations', []))}".lower()
    product_match = product.lower() in haystack
    version_match = version.lower() in haystack
    if product_match and version_match:
        return "high"
    if product_match or version_match:
        return "medium"
    return "low"


def _cve_evidence(cve: dict[str, Any], description: str, product: str, version: str, confidence: str) -> str:
    return (
        f"keywordSearch={product} {version}; confidence={confidence}; "
        f"description_match={product.lower() in description.lower() and version.lower() in description.lower()}; "
        f"source={cve.get('sourceIdentifier', 'NVD')}"
    )


def _english_description(descriptions: list[dict[str, Any]]) -> str:
    for description in descriptions:
        if description.get("lang") == "en":
            return description.get("value", "")
    return descriptions[0].get("value", "") if descriptions else ""


def _inventory_finding(candidates: list[dict[str, str]], evidence: str) -> Finding:
    return build_finding(
        "CVE_SERVICE_INVENTORY",
        "cve",
        "CVE/CVSS analysis structure",
        PASS if candidates else WARNING,
        RISK_INFO,
        evidence,
        "Collect service banners or package inventories to enable CVE matching." if not candidates else "No action required.",
        description="CVE lookup is based on detected product/version evidence and remains advisory until manually verified.",
        metadata={
            "services": candidates,
        },
    )


def _lookup_evidence(lookup: dict[str, Any]) -> str:
    if lookup.get("errors"):
        return "; ".join(lookup["errors"])
    if lookup.get("queries"):
        return "; ".join(query.get("evidence", "") for query in lookup["queries"])
    return "No service/version evidence was available for CVE lookup."


def _query_record(product: str, version: str, status: str, evidence: str) -> dict[str, str]:
    return {
        "product": product,
        "version": version,
        "status": status,
        "evidence": evidence,
        "queried_at": datetime.now(timezone.utc).isoformat(),
    }


def _cache_entry(product: str, version: str, items: list[dict[str, Any]], error: str | None) -> dict[str, Any]:
    return {
        "queried_at": datetime.now(timezone.utc).isoformat(),
        "product": product,
        "version": version,
        "response_summary": {
            "count": len(items),
            "error": error,
        },
        "items": items,
    }


def _load_cache() -> dict[str, Any]:
    if not CACHE_PATH.exists():
        return {}
    try:
        with CACHE_PATH.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_cache(cache: dict[str, Any]) -> None:
    CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with CACHE_PATH.open("w", encoding="utf-8") as file:
        json.dump(cache, file, indent=2, ensure_ascii=False)
        file.write("\n")


def _cache_key(product: str, version: str) -> str:
    return f"{product.lower()}::{version.lower()}"
