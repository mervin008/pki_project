#!/usr/bin/env python3
"""Turn core/api/router.go into a machine-readable route inventory.

The API reference used to be maintained by hand, which meant that adding a
route and forgetting to document it produced no signal at all — the docs simply
stayed wrong until somebody noticed. This script makes the route table a
generated artefact so that omission becomes a failing build instead.

It deliberately parses the router rather than reflecting over a running server:
the role gate on a route is the security-relevant part, and it is visible in the
source as `RequireRole(...)` but invisible in a `gin.RoutesInfo` dump, which
reports only the final handler name.

Output is JSON on stdout, or to the path given as the first argument.
"""

from __future__ import annotations

import json
import pathlib
import re
import sys

ROUTER = pathlib.Path("core/api/router.go")
MIDDLEWARE = pathlib.Path("core/server/middleware/auth.go")
DISPLAY_TOKEN = pathlib.Path("core/server/middleware/display_token.go")

# `v1.GET("/certificates", middleware.RequireRole(...), certHandler.List)`
ROUTE_RE = re.compile(
    r'^\s*(?P<group>\w+)\.(?P<method>GET|POST|PUT|PATCH|DELETE)\('
    r'"(?P<path>[^"]*)"(?P<rest>.*)$'
)
ROLE_RE = re.compile(r'RequireRole\(middleware\.Role(?P<role>\w+)\)')
HANDLER_RE = re.compile(r'(?P<recv>\w+)\.(?P<fn>\w+)\)\s*$')
SECTION_RE = re.compile(r'^\s*//\s*──\s*(?P<title>.+?)\s*──\s*$')

# Which gin group carries which prefix and authentication scheme. Taken from
# the Group() calls in SetupRouter; asserted below so that renaming a group
# fails loudly rather than silently dropping its routes.
GROUPS = {
    "engine":     {"prefix": "",                "auth": "none"},
    "agentGroup": {"prefix": "/api/v1/agent",   "auth": "agent-enrolment-token"},
    "signed":     {"prefix": "/api/v1/agent",   "auth": "agent-signature"},
    "v1":         {"prefix": "/api/v1",         "auth": "bearer"},
}


def read(path: pathlib.Path) -> str:
    if not path.exists():
        sys.exit(f"{path} not found — run this from the repository root")
    return path.read_text()


def forbidden_paths() -> list[str]:
    """The display-token deny list, read from the middleware that enforces it."""
    src = read(DISPLAY_TOKEN)
    block = re.search(
        r'displayTokenForbiddenPaths\s*=\s*\[\]string\{(.*?)\n\}', src, re.S)
    if not block:
        sys.exit("could not find displayTokenForbiddenPaths — has the "
                 "middleware been restructured?")
    # The entries are interleaved with comments that themselves quote paths and
    # email addresses, so the comments have to go before the strings are read —
    # otherwise the deny list picks up prose.
    body = "\n".join(
        line for line in block.group(1).splitlines()
        if not line.strip().startswith("//")
    )
    return re.findall(r'"([^"]+)"', body)


def known_roles() -> list[str]:
    src = read(MIDDLEWARE)
    block = re.search(r'RBAC roles.*?const \((.*?)\)', src, re.S)
    if not block:
        sys.exit("could not find the RBAC role constants")
    return re.findall(r'Role\w+\s*=\s*"(\w+)"', block.group(1))


def collect_comment(lines: list[str], index: int) -> str:
    """The contiguous `//` block immediately above a route.

    The router's comments explain why a route is gated where it is, and that
    reasoning is the most useful thing in the file. Carrying it through means
    the reference explains the rule rather than only stating it.
    """
    out: list[str] = []
    i = index - 1
    while i >= 0:
        stripped = lines[i].strip()
        if not stripped.startswith("//"):
            break
        if SECTION_RE.match(lines[i]):
            break
        out.append(stripped.lstrip("/").strip())
        i -= 1
    return " ".join(reversed(out)).strip()


def main() -> None:
    src = read(ROUTER)
    lines = src.splitlines()

    for name in ("agentGroup", "signed", "v1"):
        if f"{name} :=" not in src and f"{name} := " not in src:
            sys.exit(f"group {name!r} no longer exists in router.go — "
                     "GROUPS in this script is out of date")

    deny = forbidden_paths()
    roles = known_roles()

    routes: list[dict] = []
    section = ""

    for n, line in enumerate(lines):
        if match := SECTION_RE.match(line):
            section = match.group("title")
            continue

        match = ROUTE_RE.match(line)
        if not match:
            continue

        group = match.group("group")
        if group not in GROUPS:
            continue

        meta = GROUPS[group]
        path = meta["prefix"] + match.group("path")
        method = match.group("method")
        rest = match.group("rest")

        role_match = ROLE_RE.search(rest)
        if role_match:
            role = role_match.group("role").lower()
            if role not in roles:
                sys.exit(f"{path}: role {role!r} is not one of {roles}")
        elif meta["auth"] == "bearer":
            # No gate means any authenticated caller, which is viewer upwards.
            role = "viewer"
        else:
            role = None

        handler_match = HANDLER_RE.search(rest)
        handler = (f'{handler_match.group("recv")}.{handler_match.group("fn")}'
                   if handler_match else None)

        # A display token is viewer-role, GET-only, and refused outright on the
        # deny list — all three enforced centrally in DisplayTokenAuth.
        display_ok = (
            meta["auth"] == "bearer"
            and method == "GET"
            and role == "viewer"
            and not any(d in path for d in deny)
        )

        routes.append({
            "method": method,
            "path": path,
            "section": section,
            "handler": handler,
            "auth": meta["auth"],
            "min_role": role,
            "display_token": display_ok,
            "note": collect_comment(lines, n),
            "source_line": n + 1,
        })

    routes.sort(key=lambda r: (r["path"], r["method"]))

    document = {
        "source": str(ROUTER),
        "route_count": len(routes),
        "roles": roles,
        "display_token_denied_paths": deny,
        "routes": routes,
    }

    text = json.dumps(document, indent=2) + "\n"
    if len(sys.argv) > 1:
        pathlib.Path(sys.argv[1]).write_text(text)
        print(f"{len(routes)} routes → {sys.argv[1]}", file=sys.stderr)
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()
