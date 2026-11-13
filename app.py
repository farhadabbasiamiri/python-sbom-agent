
import gradio as gr
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parent


def scan_dependencies(file):
    if file is None:
        return "Please upload a file first.", [], {}, "", None

    if Path(file).suffix.lower() != ".txt":
        return "Please upload a .txt file.", [], {}, "", None

    if Path(file).stat().st_size > 1024 * 1024:
        return "File must be smaller than 1 MB.", [], {}, "", None

    try:
        # Create a separate folder for this scan
        with tempfile.TemporaryDirectory() as work_dir:
            input_path = Path(work_dir) / "requirments.txt"
            output_path = Path(work_dir) / "scan_results.json"

            shutil.copyfile(file, input_path)

            # Allow the scanner to import the team's modules
            env = os.environ.copy()
            env["PYTHONPATH"] = (
                str(PROJECT_DIR)
                + os.pathsep
                + env.get("PYTHONPATH", "")
            )

            # Run the existing scanner
            result = subprocess.run(
                [sys.executable, str(PROJECT_DIR / "main.py")],
                cwd=work_dir,
                env=env,
                capture_output=True,
                text=True,
                timeout=180
            )

            if result.returncode != 0:
                return (
                    f"Scanner error:\n{result.stderr[-2000:]}",
                    [], {}, "", None
                )

            if not output_path.exists():
                return (
                    "Scanner did not generate a report.",
                    [], {}, "", None
                )

            with open(output_path, encoding="utf-8") as f:
                scan_results = json.load(f)

            if not isinstance(scan_results, list):
                raise ValueError("Unexpected scanner report format.")

            # Build the dashboard results table
            table = []
            summaries = []

            for package in scan_results:
                upgrade = package.get("upgrade_recommendation") or {}
                agent = package.get("agent_analysis") or {}

                if not isinstance(upgrade, dict):
                    upgrade = {}
                if not isinstance(agent, dict):
                    agent = {}

                table.append([
                    str(package.get("package", "")),
                    str(package.get("version", "")),
                    package.get("unique_vulnerability_count", 0),
                    package.get("risk_score"),
                    str(upgrade.get("recommended_candidate") or "Not verified"),
                    str(upgrade.get("status") or "Unknown")
                ])

                actions = agent.get("recommended_actions") or []
                if not isinstance(actions, list):
                    actions = [str(actions)]

                summaries.append(
                    f"### {package.get('package', 'Unknown package')}\n"
                    f"{agent.get('summary', 'No analysis available.')}\n\n"
                    + "\n".join(f"- {action}" for action in actions)
                )

            # Preserve a downloadable copy of the report
            fd, report_path = tempfile.mkstemp(suffix=".json")
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(scan_results, f, indent=4)

            status = (
                f"Scan completed. Analyzed {len(scan_results)} "
                "package(s). Review the findings below."
            )

            if "API request failed" in result.stdout:
                status += (
                    "\nWarning: Some API requests failed. "
                    "The results may be incomplete."
                )

            return (
                status,
                table,
                scan_results,
                "\n\n".join(summaries),
                report_path
            )

    except subprocess.TimeoutExpired:
        return "Scan timed out after 180 seconds.", [], {}, "", None

    except Exception as error:
        return f"Error: {error}", [], {}, "", None


with gr.Blocks(
    title="Python Dependency SBOM Risk Agent"
) as demo:

    gr.Markdown("# Python Dependency SBOM Risk Agent")
    gr.Markdown("### Group 10A | Laurentian University")
    gr.Markdown(
        "Upload a Python dependency file to scan for known "
        "security vulnerabilities using the OSV database."
    )

    with gr.Row():
        file_input = gr.File(
            label="Upload requirements.txt",
            file_types=[".txt"],
            type="filepath"
        )

    scan_button = gr.Button(
        "Scan Dependencies",
        variant="primary"
    )

    status = gr.Textbox(
        label="Scan Status",
        interactive=False
    )

    gr.Markdown("## Vulnerability Assessment")

    results_table = gr.Dataframe(
        headers=[
            "Package",
            "Installed Version",
            "Vulnerabilities",
            "Risk Score",
            "Upgrade Candidate",
            "Upgrade Status"
        ],
        interactive=False
    )

    with gr.Tab("Detailed Vulnerability Results"):
        json_output = gr.JSON(
            label="OSV Scan Results"
        )

    with gr.Tab("Security Agent Analysis"):
        agent_output = gr.Markdown()

    gr.Markdown("## Download Security Report")

    report_file = gr.File(
        label="Download JSON Report",
        interactive=False
    )

    scan_button.click(
        fn=scan_dependencies,
        inputs=[file_input],
        outputs=[
            status,
            results_table,
            json_output,
            agent_output,
            report_file
        ]
    )

if __name__ == "__main__":
    demo.launch()
