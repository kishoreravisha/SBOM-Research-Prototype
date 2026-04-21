import json
import os
import subprocess
import time
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Any, Optional

import requests


OSV_API_URL = "https://api.osv.dev/v1/query"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

ECOSYSTEM_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "golang": "Go",
    "go": "Go",
    "cargo": "crates.io",
    "nuget": "NuGet",
    "composer": "Packagist",
    "gem": "RubyGems",
    "pub": "Pub",
}

SEVERITY_TO_SCORE = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MODERATE": 5.5,
    "MEDIUM": 5.5,
    "LOW": 2.5,
    "NONE": 0.0,
}


def run_syft(target_path: str, output_file: str = "sbom.json") -> str:
    """Generate a CycloneDX JSON SBOM using Syft."""
    try:
        result = subprocess.run(
            ["syft", target_path, "-o", "cyclonedx-json"],
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("Syft is not installed or not in PATH. Install Syft first.") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Syft failed:\n{exc.stderr}") from exc

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(result.stdout)

    return output_file


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def clean_purl(purl: str) -> str:
    return purl.split("#")[0] if purl else ""


def ecosystem_from_component(component: Dict[str, Any]) -> Optional[str]:
    purl = component.get("purl", "")
    if purl.startswith("pkg:"):
        kind = purl[4:].split("/")[0].split("@")[0].split("?")[0].lower()
        return ECOSYSTEM_MAP.get(kind)
    comp_type = (component.get("type") or "").lower()
    return ECOSYSTEM_MAP.get(comp_type)


def build_component_index(sbom: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    components = sbom.get("components", [])
    index = {}

    for c in components:
        ref = c.get("bom-ref") or c.get("purl") or f"{c.get('name')}@{c.get('version', 'unknown')}"
        index[ref] = {
            "ref": ref,
            "name": c.get("name", "unknown"),
            "version": c.get("version", "unknown"),
            "type": c.get("type", "unknown"),
            "purl": clean_purl(c.get("purl", "")),
            "ecosystem": ecosystem_from_component(c),
        }

    return index


def build_dependency_graph(sbom: Dict[str, Any]) -> Tuple[Dict[str, List[str]], Dict[str, List[str]]]:
    """CycloneDX dependency entry: ref -> dependsOn[]"""
    graph = defaultdict(list)
    reverse_graph = defaultdict(list)

    for dep in sbom.get("dependencies", []):
        parent = dep.get("ref")
        if not parent:
            continue
        graph.setdefault(parent, [])
        for child in dep.get("dependsOn", []):
            graph[parent].append(child)
            reverse_graph[child].append(parent)
            graph.setdefault(child, [])
            reverse_graph.setdefault(parent, reverse_graph.get(parent, []))

    return dict(graph), dict(reverse_graph)


def find_roots(sbom: Dict[str, Any], graph: Dict[str, List[str]], reverse_graph: Dict[str, List[str]]) -> List[str]:
    all_nodes = set(graph.keys()) | set(reverse_graph.keys())

    metadata_component = (sbom.get("metadata") or {}).get("component") or {}
    metadata_ref = metadata_component.get("bom-ref")

    if metadata_ref and metadata_ref in all_nodes:
        return [metadata_ref]

    return [node for node in all_nodes if len(reverse_graph.get(node, [])) == 0]


def compute_depths(sbom: Dict[str, Any], graph: Dict[str, List[str]], reverse_graph: Dict[str, List[str]]) -> Dict[str, Optional[int]]:
    roots = find_roots(sbom, graph, reverse_graph)
    depths: Dict[str, Optional[int]] = {}

    q = deque()
    for root in roots:
        depths[root] = 0
        q.append(root)

    while q:
        current = q.popleft()
        for nxt in graph.get(current, []):
            new_depth = depths[current] + 1
            if nxt not in depths or (depths[nxt] is not None and new_depth < depths[nxt]):
                depths[nxt] = new_depth
                q.append(nxt)

    for node in set(graph.keys()) | set(reverse_graph.keys()):
        depths.setdefault(node, None)

    return depths


def classify_dependency(depth: Optional[int]) -> str:
    if depth == 0:
        return "Root"
    if depth == 1:
        return "Direct"
    if depth is not None and depth > 1:
        return "Transitive"
    return "Unknown"


def extract_osv_severity(vuln: Dict[str, Any]) -> str:
    for affected in vuln.get("affected", []):
        eco = affected.get("ecosystem_specific", {})
        sev = eco.get("severity")
        if sev:
            return sev.upper()

    for sev in vuln.get("severity", []):
        score_text = sev.get("score", "")
        upper = score_text.upper()
        if "CRITICAL" in upper:
            return "CRITICAL"
        if "HIGH" in upper:
            return "HIGH"
        if "MEDIUM" in upper:
            return "MEDIUM"
        if "LOW" in upper:
            return "LOW"

    return "NONE"


def query_osv(name: str, version: str, ecosystem: Optional[str], purl: str) -> List[Dict[str, Any]]:
    if purl:
        if "@" in purl:
            payload = {"package": {"purl": purl}}
        else:
            payload = {"package": {"purl": purl}, "version": version}
    elif ecosystem and name and version:
        payload = {"package": {"name": name, "ecosystem": ecosystem}, "version": version}
    else:
        return []

    vulns: List[Dict[str, Any]] = []
    page_token = None

    while True:
        request_payload = dict(payload)
        if page_token:
            request_payload["page_token"] = page_token

        try:
            resp = requests.post(OSV_API_URL, json=request_payload, timeout=30)
            resp.raise_for_status()
            data = resp.json()
        except Exception:
            break

        vulns.extend(data.get("vulns", []))
        page_token = data.get("next_page_token")
        if not page_token:
            break

    return vulns


def pick_best_cvss(metrics: Dict[str, Any]) -> Tuple[float, str]:
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if key in metrics and metrics[key]:
            metric = metrics[key][0]
            cvss_data = metric.get("cvssData", {})
            score = cvss_data.get("baseScore", 0.0)
            severity = metric.get("baseSeverity") or cvss_data.get("baseSeverity") or "UNKNOWN"
            return float(score), str(severity).upper()
    return 0.0, "UNKNOWN"


def query_nvd_cvss(cve_id: str, api_key: Optional[str] = None) -> Dict[str, Any]:
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id},
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception:
        return {}

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return {}

    cve_obj = vulns[0].get("cve", {})
    score, severity = pick_best_cvss(cve_obj.get("metrics", {}))

    return {"cve_id": cve_id, "cvss": score, "severity": severity}


def extract_best_vulnerability(osv_vulns: List[Dict[str, Any]], nvd_api_key: Optional[str] = None) -> Dict[str, Any]:
    best = {"cve_id": "", "cvss": 0.0, "severity": "NONE", "osv_id": "", "summary": ""}

    for vuln in osv_vulns:
        aliases = vuln.get("aliases", []) or []
        cves = [a for a in aliases if isinstance(a, str) and a.startswith("CVE-")]

        osv_severity = extract_osv_severity(vuln)
        fallback_score = SEVERITY_TO_SCORE.get(osv_severity, 0.0)

        local_best_score = fallback_score
        local_best_cve = ""
        local_best_severity = osv_severity

        for cve in cves:
            nvd_data = query_nvd_cvss(cve, api_key=nvd_api_key)
            score = nvd_data.get("cvss", fallback_score)
            severity = nvd_data.get("severity", osv_severity)
            if score > local_best_score:
                local_best_score = score
                local_best_cve = cve
                local_best_severity = severity

        if local_best_score > best["cvss"]:
            best = {
                "cve_id": local_best_cve,
                "cvss": round(local_best_score, 2),
                "severity": local_best_severity,
                "osv_id": vuln.get("id", ""),
                "summary": vuln.get("summary", ""),
            }

    return best


def compute_risk_score(cvss: float, dependency_depth: Optional[int], downstream_dependents: int) -> float:
    depth_score = 10 if dependency_depth == 1 else 7 if dependency_depth == 2 else 4 if dependency_depth and dependency_depth >= 3 else 3
    criticality_score = min(10, downstream_dependents * 2)
    risk = (0.65 * cvss) + (0.20 * criticality_score) + (0.15 * depth_score)
    return round(risk, 2)


def analyze_project(target_path: str, sbom_file: str = "sbom.json", max_components: int = 40) -> Dict[str, Any]:
    nvd_api_key = os.getenv("NVD_API_KEY")

    run_syft(target_path, output_file=sbom_file)
    sbom = load_json(sbom_file)

    component_index = build_component_index(sbom)
    graph, reverse_graph = build_dependency_graph(sbom)
    depths = compute_depths(sbom, graph, reverse_graph)

    rows = []
    for i, comp in enumerate(component_index.values()):
        if i >= max_components:
            break

        osv_vulns = query_osv(
            name=comp["name"],
            version=comp["version"],
            ecosystem=comp["ecosystem"],
            purl=comp["purl"],
        )
        best_vuln = extract_best_vulnerability(osv_vulns, nvd_api_key=nvd_api_key)

        depth = depths.get(comp["ref"])
        dependency_level = classify_dependency(depth)
        downstream_dependents = len(reverse_graph.get(comp["ref"], []))
        risk_score = compute_risk_score(best_vuln["cvss"], depth, downstream_dependents)

        rows.append(
            {
                "component": comp["name"],
                "version": comp["version"],
                "type": comp["type"],
                "ecosystem": comp["ecosystem"] or "Unknown",
                "dependency_level": dependency_level,
                "depth": depth if depth is not None else -1,
                "downstream_dependents": downstream_dependents,
                "cve_id": best_vuln["cve_id"],
                "osv_id": best_vuln["osv_id"],
                "cvss": best_vuln["cvss"],
                "severity": best_vuln["severity"],
                "risk_score": risk_score,
                "summary": best_vuln["summary"],
            }
        )

        time.sleep(0.05)

    edges = []
    for parent, children in graph.items():
        for child in children:
            parent_name = component_index.get(parent, {}).get("name", parent)
            child_name = component_index.get(child, {}).get("name", child)
            edges.append({"from": parent_name, "to": child_name})

    total_components = len(component_index)
    vulnerable_components = sum(1 for r in rows if r["cvss"] > 0)

    return {
        "sbom_file": sbom_file,
        "total_components": total_components,
        "scanned_components": len(rows),
        "vulnerable_components": vulnerable_components,
        "results": rows,
        "edges": edges,
    }
