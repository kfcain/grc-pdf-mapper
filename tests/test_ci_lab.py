from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]


def test_ci_doc_impact_blocks_softened_mfa(tmp_path: Path):
    base = tmp_path / "base.md"
    head = tmp_path / "head.md"
    src = (ROOT / "lab" / "policies" / "access-control.md").read_text(encoding="utf-8")
    base.write_text(src, encoding="utf-8")
    head.write_text(
        src.replace(
            "Privileged accounts must use multi-factor authentication.",
            "Privileged accounts should use multi-factor authentication when feasible.",
        ),
        encoding="utf-8",
    )

    comment = tmp_path / "comment.md"
    alert = tmp_path / "alert.json"
    store = tmp_path / "store"

    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "ci_doc_impact.py"),
            "--base-file",
            str(base),
            "--head-file",
            str(head),
            "--doc-id",
            "pol-ac-001",
            "--assessments",
            str(ROOT / "lab" / "assessments.json"),
            "--store",
            str(store),
            "--fail-on",
            "high",
            "--comment-out",
            str(comment),
            "--json-out",
            str(alert),
            "--offline",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 1, proc.stdout + proc.stderr
    body = comment.read_text(encoding="utf-8")
    assert "Document change impact" in body
    assert "Frameworks that may be affected" in body
    assert "Assessments" in body
    assert alert.exists()
