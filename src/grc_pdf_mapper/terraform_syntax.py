"""Small HCL lexical helpers shared by scanning and classification."""

from __future__ import annotations

import re


_HEREDOC_START_RE = re.compile(
    r"<<-?\s*(?P<delimiter>[A-Za-z_][A-Za-z0-9_]*)"
)


def mask_hcl_non_code(text: str, *, mask_strings: bool = True) -> str:
    """Mask comments, strings, and heredocs while preserving offsets.

    Set ``mask_strings`` to false when configuration strings are evidence, but
    comments and heredoc program bodies must still be excluded.
    """
    masked = list(text)

    def blank(start: int, end: int) -> None:
        for index in range(start, min(end, len(masked))):
            if masked[index] not in {"\n", "\r"}:
                masked[index] = " "

    i = 0
    while i < len(text):
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = len(text) if end < 0 else end + 2
            blank(i, end)
            i = end
            continue
        if text.startswith("//", i) or text[i] == "#":
            end = text.find("\n", i)
            end = len(text) if end < 0 else end
            blank(i, end)
            i = end
            continue
        heredoc = _HEREDOC_START_RE.match(text, i)
        if heredoc:
            delimiter = heredoc.group("delimiter")
            marker_end = text.find("\n", heredoc.end())
            if marker_end < 0:
                blank(i, len(text))
                break
            cursor = marker_end + 1
            heredoc_end = len(text)
            while cursor <= len(text):
                line_end = text.find("\n", cursor)
                if line_end < 0:
                    line_end = len(text)
                if text[cursor:line_end].strip() == delimiter:
                    heredoc_end = line_end
                    break
                if line_end >= len(text):
                    break
                cursor = line_end + 1
            blank(i, heredoc_end)
            i = heredoc_end
            continue
        if text[i] == '"':
            end = i + 1
            while end < len(text):
                if text[end] == "\\":
                    end += 2
                    continue
                if text[end] == '"':
                    end += 1
                    break
                end += 1
            if mask_strings:
                blank(i, end)
            i = end
            continue
        i += 1
    return "".join(masked)
