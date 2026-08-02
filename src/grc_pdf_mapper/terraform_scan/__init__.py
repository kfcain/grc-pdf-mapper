"""Parse Terraform files for resources and GRC annotations."""

from __future__ import annotations

import re
from pathlib import Path

from grc_pdf_mapper.pac_models import TerraformResourceRef

_RESOURCE_RE = re.compile(
    r'resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{',
    re.MULTILINE,
)
_ANNOTATION_RE = re.compile(
    r"#\s*grc:\s*(?P<body>.+)$",
    re.IGNORECASE | re.MULTILINE,
)
_TAG_PAIR_RE = re.compile(r'([A-Za-z0-9_.-]+)\s*=\s*"([^"]*)"')


def scan_terraform_tree(root: str | Path) -> list[TerraformResourceRef]:
    root = Path(root)
    refs: list[TerraformResourceRef] = []
    for path in sorted(root.rglob("*.tf")):
        refs.extend(parse_terraform_file(path))
    return refs


def parse_terraform_file(path: str | Path) -> list[TerraformResourceRef]:
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    refs: list[TerraformResourceRef] = []

    for match in _RESOURCE_RE.finditer(text):
        start = match.start()
        start_line = text.count("\n", 0, start) + 1
        block = _extract_block(text, match.end() - 1)
        address = f"{match.group('type')}.{match.group('name')}"
        tags = _extract_tags(block)
        # Annotations on the lines immediately above the resource.
        preamble_start = max(0, start_line - 6)
        preamble = "\n".join(lines[preamble_start:start_line])
        annotations = _extract_annotations(preamble + "\n" + block)
        refs.append(
            TerraformResourceRef(
                address=address,
                resource_type=match.group("type"),
                name=match.group("name"),
                file_path=str(path),
                start_line=start_line,
                tags=tags,
                grc_annotations=annotations,
                raw_snippet=block[:500],
            )
        )
    return refs


def diff_terraform_refs(
    before: list[TerraformResourceRef],
    after: list[TerraformResourceRef],
) -> dict[str, list[TerraformResourceRef]]:
    before_map = {r.address: r for r in before}
    after_map = {r.address: r for r in after}
    added = [after_map[a] for a in after_map.keys() - before_map.keys()]
    removed = [before_map[a] for a in before_map.keys() - after_map.keys()]
    changed: list[TerraformResourceRef] = []
    for address in before_map.keys() & after_map.keys():
        b, a = before_map[address], after_map[address]
        if b.raw_snippet != a.raw_snippet or b.tags != a.tags or b.grc_annotations != a.grc_annotations:
            changed.append(a)
    return {"added": added, "removed": removed, "changed": changed}


def _extract_block(text: str, open_brace_index: int) -> str:
    depth = 0
    for i in range(open_brace_index, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace_index : i + 1]
    return text[open_brace_index : open_brace_index + 400]


def _extract_tags(block: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    # Prefer a tags = { ... } block when present.
    tags_match = re.search(r"tags\s*=\s*\{([^{}]*)\}", block, re.DOTALL)
    blob = tags_match.group(1) if tags_match else block
    for key, value in _TAG_PAIR_RE.findall(blob):
        if key in {"name", "Name"} or key.startswith("grc_") or key in {
            "policy_statement",
            "control_id",
            "doc_id",
            "link_id",
        }:
            tags[key] = value
    return tags


def _extract_annotations(text: str) -> dict[str, str]:
    annotations: dict[str, str] = {}
    for match in _ANNOTATION_RE.finditer(text):
        body = match.group("body").strip()
        for part in re.split(r"[;,]\s*", body):
            if "=" in part:
                key, value = part.split("=", 1)
                annotations[key.strip()] = value.strip().strip('"')
    return annotations
