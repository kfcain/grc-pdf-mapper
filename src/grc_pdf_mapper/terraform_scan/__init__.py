"""Parse Terraform files for resources and GRC annotations."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from pathlib import Path
from collections.abc import Iterable

from grc_pdf_mapper.pac_models import TerraformResourceRef
from grc_pdf_mapper.terraform_classify import classify_terraform_resource
from grc_pdf_mapper.terraform_syntax import mask_hcl_non_code as _mask_hcl_non_code

_RESOURCE_TOKEN_RE = re.compile(r"\bresource\b")
_RESOURCE_DECL_RE = re.compile(
    r'resource\s+"(?P<type>[^"]+)"\s+"(?P<name>[^"]+)"\s*\{',
    re.MULTILINE,
)
_ANNOTATION_RE = re.compile(
    r"(?:#|//)\s*grc:\s*(?P<body>.+)$",
    re.IGNORECASE | re.MULTILINE,
)
_ANNOTATION_PAIR_RE = re.compile(
    r"(?:^|[;,])\s*(?P<key>[A-Za-z0-9_.-]+)\s*=",
)
_TAG_PAIR_RE = re.compile(
    r'(?:(?:"(?P<quoted_key>[A-Za-z0-9_.-]+)")|(?P<key>[A-Za-z0-9_.-]+))'
    r'\s*=\s*"(?P<value>[^"]*)"'
)
_EXCLUDED_TREE_PARTS = {
    ".git",
    ".terraform",
    ".terragrunt-cache",
    ".venv",
    "node_modules",
}


def scan_terraform_tree(
    root: str | Path,
    *,
    repository: str = "",
    revision: str = "",
    root_path: str = "",
    reject_symlinks: bool = True,
) -> list[TerraformResourceRef]:
    """Scan all Terraform resources under one local tree."""
    root = Path(root)
    if root.is_symlink():
        if reject_symlinks:
            raise ValueError(f"Terraform root must not be a symlink: {root}")
        return []
    refs: list[TerraformResourceRef] = []
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        kept_directories: list[str] = []
        for name in sorted(directories):
            child = current_path / name
            if name in _EXCLUDED_TREE_PARTS:
                continue
            if child.is_symlink():
                if reject_symlinks:
                    raise ValueError(
                        f"Terraform input directory must not be a symlink: {child}"
                    )
                continue
            kept_directories.append(name)
        directories[:] = kept_directories
        for name in sorted(files):
            if not name.lower().endswith(".tf"):
                continue
            path = current_path / name
            if path.is_symlink():
                if reject_symlinks:
                    raise ValueError(f"Terraform input must not be a symlink: {path}")
                continue
            refs.extend(
                parse_terraform_file(
                    path,
                    root=root,
                    repository=repository,
                    revision=revision,
                    root_path=root_path,
                )
            )
    return refs


def parse_terraform_file(
    path: str | Path,
    *,
    root: str | Path | None = None,
    repository: str = "",
    revision: str = "",
    root_path: str = "",
) -> list[TerraformResourceRef]:
    path = Path(path)
    if path.is_symlink():
        raise ValueError(f"Terraform input must not be a symlink: {path}")
    tree_root = Path(root) if root is not None else None
    if tree_root is not None:
        try:
            relative_path = path.relative_to(tree_root).as_posix()
        except ValueError:
            relative_path = path.name
        parent = Path(relative_path).parent.as_posix()
        module_path = "." if parent in {"", "."} else parent
    else:
        # Direct base/head files often have different temporary names. Treat
        # both as the same root module so their resource addresses still pair.
        relative_path = path.name
        module_path = "."
    prefix = Path(root_path).as_posix().strip("./")
    if prefix:
        relative_path = f"{prefix}/{relative_path}"
        parent = Path(relative_path).parent.as_posix()
        module_path = "." if parent in {"", "."} else parent
    text = path.read_text(encoding="utf-8")
    return parse_terraform_text(
        text,
        file_path=str(path),
        relative_path=relative_path,
        module_path=module_path,
        repository=repository,
        revision=revision,
        root_path=prefix,
    )


def parse_terraform_text(
    text: str,
    *,
    file_path: str,
    relative_path: str,
    module_path: str,
    repository: str = "",
    revision: str = "",
    root_path: str = "",
) -> list[TerraformResourceRef]:
    """Parse Terraform text with an explicit repository identity."""
    lines = text.splitlines()
    refs: list[TerraformResourceRef] = []
    masked = _mask_hcl_non_code(text)

    for token in _RESOURCE_TOKEN_RE.finditer(masked):
        match = _RESOURCE_DECL_RE.match(text, token.start())
        if match is None:
            continue
        start = match.start()
        start_line = text.count("\n", 0, start) + 1
        open_brace = match.end() - 1
        block_end = _find_block_end(masked, open_brace)
        block = text[open_brace:block_end]
        semantic_block = _mask_hcl_non_code(block, mask_strings=False)
        address = f"{match.group('type')}.{match.group('name')}"
        tags = _extract_tags(semantic_block)
        preamble = _annotation_preamble(lines, start_line - 1)
        annotations = _extract_annotations(preamble)
        classification = classify_terraform_resource(
            match.group("type"),
            semantic_block,
            tags=tags,
            annotations=annotations,
        )
        refs.append(
            TerraformResourceRef(
                address=address,
                resource_type=match.group("type"),
                name=match.group("name"),
                file_path=file_path,
                relative_path=relative_path,
                module_path=module_path,
                repository=repository,
                revision=revision,
                root_path=root_path,
                start_line=start_line,
                tags=tags,
                grc_annotations=annotations,
                classification=classification,
                content_hash=hashlib.sha256(block.encode("utf-8")).hexdigest(),
                raw_snippet=block[:500],
            )
        )
    return refs


def scan_terraform_revision(
    repository_root: str | Path,
    revision: str,
    terraform_roots: Iterable[str],
    *,
    repository: str = "",
) -> list[TerraformResourceRef]:
    """Read Terraform files from one Git revision without a worktree checkout."""
    repository_root = Path(repository_root)
    revision = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "rev-parse",
            "--verify",
            f"{revision}^{{commit}}",
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    roots = [_clean_repo_path(value) for value in terraform_roots]
    pathspecs = roots or ["."]
    result = subprocess.run(
        [
            "git",
            "-C",
            str(repository_root),
            "ls-tree",
            "-r",
            "--name-only",
            revision,
            "--",
            *pathspecs,
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    paths = sorted(
        {
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip().endswith(".tf")
            and not any(
                part in _EXCLUDED_TREE_PARTS
                for part in Path(line.strip()).parts
            )
        }
    )
    refs: list[TerraformResourceRef] = []
    for relative_path in paths:
        content = subprocess.run(
            [
                "git",
                "-C",
                str(repository_root),
                "show",
                f"{revision}:{relative_path}",
            ],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        parent = Path(relative_path).parent.as_posix()
        root_path = _matching_root(relative_path, roots)
        refs.extend(
            parse_terraform_text(
                content,
                file_path=f"git:{repository}@{revision}:{relative_path}",
                relative_path=relative_path,
                module_path="." if parent in {"", "."} else parent,
                repository=repository,
                revision=revision,
                root_path=root_path,
            )
        )
    return refs


def diff_terraform_refs(
    before: list[TerraformResourceRef],
    after: list[TerraformResourceRef],
) -> dict[str, list[TerraformResourceRef]]:
    before_map = {r.identity_key: r for r in before}
    after_map = {r.identity_key: r for r in after}
    added = [after_map[a] for a in sorted(after_map.keys() - before_map.keys())]
    removed = [before_map[a] for a in sorted(before_map.keys() - after_map.keys())]
    changed: list[TerraformResourceRef] = []
    for address in sorted(before_map.keys() & after_map.keys()):
        b, a = before_map[address], after_map[address]
        if (
            b.content_hash != a.content_hash
            or b.tags != a.tags
            or b.grc_annotations != a.grc_annotations
        ):
            changed.append(a)
    return {"added": added, "removed": removed, "changed": changed}


def _find_block_end(text: str, open_brace_index: int) -> int:
    depth = 0
    for i in range(open_brace_index, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    raise ValueError("Unbalanced Terraform resource block")


def _annotation_preamble(lines: list[str], declaration_index: int) -> str:
    """Return only contiguous comment lines directly above one resource."""
    selected: list[str] = []
    cursor = declaration_index - 1
    while cursor >= 0:
        stripped = lines[cursor].strip()
        if stripped.startswith(("#", "//")):
            selected.insert(0, lines[cursor])
            cursor -= 1
            continue
        break
    return "\n".join(selected)


def _extract_tags(block: str) -> dict[str, str]:
    tags: dict[str, str] = {}
    # Prefer a tags = { ... } block when present.
    tags_match = re.search(r"tags\s*=\s*\{([^{}]*)\}", block, re.DOTALL)
    blob = tags_match.group(1) if tags_match else block
    for match in _TAG_PAIR_RE.finditer(blob):
        key = match.group("quoted_key") or match.group("key") or ""
        value = match.group("value")
        normalized_key = key.lower()
        if normalized_key == "name" or normalized_key.startswith("grc_") or normalized_key in {
            "policy_statement",
            "control_id",
            "control_ids",
            "doc_id",
            "link_id",
        }:
            tags["Name" if key == "Name" else normalized_key] = value
    return tags


def _extract_annotations(text: str) -> dict[str, str]:
    annotations: dict[str, str] = {}
    for match in _ANNOTATION_RE.finditer(text):
        body = match.group("body").strip()
        pairs = list(_ANNOTATION_PAIR_RE.finditer(body))
        for index, pair in enumerate(pairs):
            value_end = pairs[index + 1].start() if index + 1 < len(pairs) else len(body)
            value = body[pair.end() : value_end].strip().strip(";,").strip().strip('"')
            if value:
                annotations[pair.group("key").strip().lower()] = value
    return annotations


def _clean_repo_path(value: str) -> str:
    normalized = Path(value).as_posix().strip("/")
    if normalized in {"", "."}:
        return "."
    if normalized == ".." or normalized.startswith("../"):
        raise ValueError(f"Terraform root must remain inside its repository: {value}")
    return normalized


def _matching_root(path: str, roots: list[str]) -> str:
    matches = [root for root in roots if root == "." or path == root or path.startswith(root + "/")]
    if not matches:
        return ""
    return max(matches, key=len)
