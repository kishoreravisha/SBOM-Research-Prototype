import sys
from scanner_core import analyze_project


def main():
    if len(sys.argv) < 2:
        print("Usage: python cli.py <project_path>")
        sys.exit(1)

    project_path = sys.argv[1]
    data = analyze_project(project_path)

    print("\n========== SBOM RESEARCH PROTOTYPE ==========")
    print(f"SBOM file              : {data['sbom_file']}")
    print(f"Total components       : {data['total_components']}")
    print(f"Scanned components     : {data['scanned_components']}")
    print(f"Vulnerable components  : {data['vulnerable_components']}")
    print("=============================================\n")

    results = sorted(data["results"], key=lambda x: x["risk_score"], reverse=True)

    print("Top risky components:\n")
    for row in results[:10]:
        print(
            f"[{row['dependency_level']}] "
            f"{row['component']} {row['version']} | "
            f"CVE={row['cve_id'] or '-'} | "
            f"CVSS={row['cvss']} | "
            f"Risk={row['risk_score']} | "
            f"Severity={row['severity']}"
        )

    print("\nDependency edges (first 15):\n")
    for edge in data["edges"][:15]:
        print(f"{edge['from']}  -->  {edge['to']}")


if __name__ == "__main__":
    main()
