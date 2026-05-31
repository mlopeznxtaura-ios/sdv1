"""
Reporter — formats ViabilityScan results for terminal and JSON output.
"""

import json
from pathlib import Path
from datetime import datetime


SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


class Reporter:
    def __init__(self, result: dict):
        self.r = result

    def print_summary(self):
        r = self.r
        scores = r["scores"]
        gate = r["gate"]
        gate_icon = "✅ PASS" if gate == "PASS" else "❌ FAIL"

        print(f"\n{'─'*60}")
        print(f"  PHASE GATE:  {gate_icon}")
        print(f"{'─'*60}")
        print(f"  Viability Score : {scores['viability']:>6.1f}  (threshold ≥75)")
        print(f"  Security        : {scores['security']:>6.1f}  (threshold ≥70)")
        print(f"  Deployment      : {scores['deployment']:>6.1f}  (threshold ≥60)")
        print(f"  Reliability     : {scores['reliability']:>6.1f}  (threshold ≥60)")
        print(f"{'─'*60}")

        if r["gate_reasons"]:
            print("\n  ⚠️  Gate failures:")
            for reason in r["gate_reasons"]:
                print(f"     • {reason}")

        print(f"\n  📦  Repository : {r['repo_name']}")
        print(f"  🕒  Scanned at : {r['scanned_at'][:19].replace('T', ' ')} UTC")
        print(f"  ⏱️   Elapsed    : {r['elapsed_seconds']}s")
        print(f"  🔍  Mode       : {r['mode'].upper()}")

        # Findings summary per layer
        print(f"\n{'─'*60}")
        print("  FINDINGS SUMMARY")
        print(f"{'─'*60}")
        for layer_name, layer_data in r.get("layers", {}).items():
            counts = layer_data.get("severity_counts", {})
            total = layer_data.get("finding_count", 0)
            if total == 0:
                print(f"  {layer_name:<22}  ✅  No findings")
                continue
            parts = []
            for sev in SEVERITY_ORDER:
                n = counts.get(sev, 0)
                if n:
                    parts.append(f"{SEVERITY_ICONS[sev]} {sev}:{n}")
            print(f"  {layer_name:<22}  {' '.join(parts)}")

        # Top findings
        all_findings = []
        for layer_data in r.get("layers", {}).values():
            all_findings.extend(layer_data.get("findings", []))

        critical_high = [f for f in all_findings if f.get("severity") in ("CRITICAL", "HIGH")]
        if critical_high:
            print(f"\n{'─'*60}")
            print("  TOP FINDINGS (CRITICAL / HIGH)")
            print(f"{'─'*60}")
            for f in critical_high[:10]:
                icon = SEVERITY_ICONS.get(f.get("severity", "INFO"), "⚪")
                loc = f.get("file", "?")
                if f.get("line"):
                    loc += f":{f['line']}"
                print(f"  {icon} {f['title']}")
                print(f"       📁 {loc}")
                print(f"       💡 {f.get('remediation','')[:100]}")
                print()

        # Next frame prediction
        print(f"{'─'*60}")
        print(f"  🔮  NEXT: {r.get('next_frame_prediction', '')}")
        print(f"{'─'*60}\n")

    def save_json(self, output_path: str):
        path = Path(output_path)
        path.write_text(json.dumps(self.r, indent=2, default=str))
        print(f"  📄  Full report saved: {path.resolve()}")
