"""
ViabilityScan Dashboard — NiceGUI three-panel interface.
Panels: Ingest | Analyze | Report

Install: pip install nicegui
Run:     python dashboard/app.py
"""

import json
import threading
from pathlib import Path

try:
    from nicegui import ui, app as ngapp
    HAS_NICEGUI = True
except ImportError:
    HAS_NICEGUI = False
    print("[WARNING] nicegui not installed. Run: pip install nicegui")

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from viabilityscan.engine import ViabilityEngine
from viabilityscan.reporter import Reporter


SEVERITY_COLORS = {
    "CRITICAL": "red-14",
    "HIGH":     "orange-10",
    "MEDIUM":   "yellow-9",
    "LOW":      "blue-6",
    "INFO":     "grey-6",
}


def build_app():
    scan_state = {
        "running": False,
        "result": None,
        "log": [],
    }

    with ui.header(elevated=True).classes("bg-slate-900 text-white"):
        ui.label("⬡ ViabilityScan").classes("text-2xl font-mono font-bold")
        ui.label("Deployment Readiness Engine v1.0").classes("text-sm text-slate-400 ml-4 self-center")

    with ui.tabs().classes("w-full bg-slate-800 text-white") as tabs:
        tab_ingest  = ui.tab("📥  Ingest")
        tab_analyze = ui.tab("🔬  Analyze")
        tab_report  = ui.tab("📊  Report")

    with ui.tab_panels(tabs, value=tab_ingest).classes("w-full"):

        # ── Panel 1: Ingest ──────────────────────────────────────────────
        with ui.tab_panel(tab_ingest):
            ui.label("Repository Ingestion").classes("text-xl font-semibold mt-4 mb-2")
            ui.separator()

            with ui.card().classes("w-full max-w-2xl mt-4"):
                repo_input = ui.input(
                    label="Repository path",
                    placeholder="/path/to/your/repo",
                    value="."
                ).classes("w-full font-mono")

                with ui.row().classes("mt-2 gap-4"):
                    full_mode = ui.checkbox("Full scan (Semgrep/Trivy/Checkov if installed)", value=False)

                ui.separator().classes("my-4")

                status_label = ui.label("Ready to scan.").classes("text-sm text-slate-500")
                progress = ui.linear_progress(value=0).classes("w-full mt-2")
                progress.visible = False

                log_area = ui.log(max_lines=20).classes("w-full font-mono text-xs mt-2 h-32")
                log_area.visible = False

            def run_scan():
                repo_path = Path(repo_input.value.strip()).resolve()
                if not repo_path.exists():
                    status_label.set_text(f"❌ Path not found: {repo_path}")
                    return

                scan_state["running"] = True
                scan_state["log"] = []
                progress.visible = True
                log_area.visible = True
                progress.set_value(0.1)
                status_label.set_text(f"⏳ Scanning {repo_path.name}...")
                log_area.push(f"[INFO] Starting scan: {repo_path}")

                def do_scan():
                    try:
                        progress.set_value(0.3)
                        log_area.push("[M1] Running security MVP layer...")
                        engine = ViabilityEngine(repo_path, full=full_mode.value)
                        progress.set_value(0.5)
                        log_area.push("[M1] Running deployment layer...")
                        result = engine.run()
                        progress.set_value(0.8)
                        log_area.push("[M3] Computing viability score...")
                        scan_state["result"] = result
                        scan_state["running"] = False
                        progress.set_value(1.0)
                        gate = result["gate"]
                        score = result["scores"]["viability"]
                        status_label.set_text(f"{'✅' if gate == 'PASS' else '❌'} {gate} — Viability: {score}")
                        log_area.push(f"[DONE] Gate: {gate}  Score: {score}")
                        tabs.set_value(tab_report)
                    except Exception as e:
                        status_label.set_text(f"❌ Error: {e}")
                        log_area.push(f"[ERROR] {e}")

                threading.Thread(target=do_scan, daemon=True).start()

            scan_btn = ui.button("🚀 Run ViabilityScan", on_click=run_scan).classes(
                "mt-4 bg-indigo-600 text-white font-semibold px-6"
            )

        # ── Panel 2: Analyze ─────────────────────────────────────────────
        with ui.tab_panel(tab_analyze):
            ui.label("Live Findings").classes("text-xl font-semibold mt-4 mb-2")
            ui.separator()

            def refresh_findings():
                findings_container.clear()
                result = scan_state.get("result")
                if not result:
                    with findings_container:
                        ui.label("No scan results yet. Run a scan in the Ingest tab.").classes("text-slate-400")
                    return
                all_findings = []
                for layer_data in result.get("layers", {}).values():
                    all_findings.extend(layer_data.get("findings", []))

                if not all_findings:
                    with findings_container:
                        ui.label("✅ No findings — repository looks clean!").classes("text-green-600 font-semibold")
                    return

                with findings_container:
                    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                        group = [f for f in all_findings if f.get("severity") == sev]
                        if not group:
                            continue
                        with ui.expansion(f"{sev} ({len(group)})", icon="warning").classes("w-full mb-2"):
                            for f in group:
                                with ui.card().classes("w-full mb-1 p-2"):
                                    ui.label(f['title']).classes("font-semibold text-sm")
                                    with ui.row().classes("text-xs text-slate-500 gap-4"):
                                        ui.label(f"📁 {f.get('file','?')}")
                                        if f.get('line'):
                                            ui.label(f"L{f['line']}")
                                        ui.label(f"[{f.get('layer','?')}]")
                                    if f.get('remediation'):
                                        ui.label(f"💡 {f['remediation']}").classes("text-xs text-indigo-700 mt-1")

            with ui.row().classes("gap-2 mb-2"):
                ui.button("🔄 Refresh", on_click=refresh_findings).classes("text-sm")

            findings_container = ui.column().classes("w-full")
            with findings_container:
                ui.label("No scan results yet.").classes("text-slate-400")

        # ── Panel 3: Report ──────────────────────────────────────────────
        with ui.tab_panel(tab_report):
            ui.label("Viability Report").classes("text-xl font-semibold mt-4 mb-2")
            ui.separator()

            def refresh_report():
                report_container.clear()
                result = scan_state.get("result")
                if not result:
                    with report_container:
                        ui.label("No scan results yet.").classes("text-slate-400")
                    return

                scores = result["scores"]
                gate = result["gate"]

                with report_container:
                    # Gate banner
                    gate_class = "bg-green-100 border-green-500" if gate == "PASS" else "bg-red-100 border-red-500"
                    with ui.card().classes(f"w-full border-l-4 {gate_class} mb-4"):
                        ui.label(f"{'✅ PASS' if gate == 'PASS' else '❌ FAIL'} — Phase Gate").classes("text-2xl font-bold")
                        for reason in result.get("gate_reasons", []):
                            ui.label(f"⚠️  {reason}").classes("text-sm text-red-700")

                    # Score cards
                    with ui.row().classes("gap-4 mb-4 flex-wrap"):
                        for label, key, threshold in [
                            ("Viability", "viability", 75),
                            ("Security",  "security",  70),
                            ("Deployment","deployment", 60),
                            ("Reliability","reliability",60),
                        ]:
                            val = scores.get(key, 0)
                            color = "green" if val >= threshold else "red"
                            with ui.card().classes(f"min-w-36 text-center border-t-4 border-{color}-500"):
                                ui.label(label).classes("text-sm text-slate-500")
                                ui.label(str(val)).classes(f"text-4xl font-bold text-{color}-600")
                                ui.label(f"≥{threshold}").classes("text-xs text-slate-400")

                    # Next frame prediction
                    with ui.card().classes("w-full bg-indigo-50 mb-4"):
                        ui.label("🔮 Next Steps").classes("font-semibold mb-1")
                        ui.label(result.get("next_frame_prediction", "")).classes("text-sm")

                    # Export JSON
                    def save_report():
                        out = Path("viability_report.json")
                        out.write_text(json.dumps(result, indent=2, default=str))
                        ui.notify(f"Report saved to {out.resolve()}", type="positive")

                    ui.button("💾 Export JSON Report", on_click=save_report).classes(
                        "bg-slate-700 text-white"
                    )

            with ui.row().classes("gap-2 mb-2"):
                ui.button("🔄 Refresh Report", on_click=refresh_report).classes("text-sm")

            report_container = ui.column().classes("w-full")
            with report_container:
                ui.label("No scan results yet.").classes("text-slate-400")

    ui.run(title="ViabilityScan", port=8765, reload=False)


if __name__ == "__main__":
    if not HAS_NICEGUI:
        print("Install nicegui: pip install nicegui")
        sys.exit(1)
    build_app()
