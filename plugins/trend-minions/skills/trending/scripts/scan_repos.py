#!/usr/bin/env python3
"""Security and prompt-injection check for GitHub repositories.

Usage:
  scan_repos.py owner/repo [owner/repo ...]
  scan_repos.py --path DIR [--path DIR ...]    scan local checkouts

For each repository it reports:
  - its OpenSSF Scorecard score (https://scorecard.dev), if it has been scored,
    and whether it has a SECURITY.md
  - its license, and whether that license allows use at work (commercial use)
  - a static scan of the files AI agents read or run (skills, agent
    instructions, hooks, MCP and agent settings, the README, install scripts)
    and of its GitHub Actions workflows, with findings in two groups:
    security (code, settings and workflows that can do harm) and prompt
    injection (text that steers an AI, hidden or not), each rated
    high / medium / low / none

Only the files that matter are downloaded: the repository is cloned without
file contents (a git partial clone) and just the selected files are fetched.
File contents are never printed, only rule names and locations, so untrusted
text from the scanned repository does not reach an agent's context. Pass
--snippets to add short, escaped excerpts for human review.

Standard library only. Remote repositories need git on PATH.
"""

import argparse
import concurrent.futures
import datetime
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import PurePosixPath

SCORECARD_API = "https://api.securityscorecards.dev/projects/github.com/{}"
SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._][A-Za-z0-9._-]*$")
MAX_FILE_BYTES = 512 * 1024
MAX_FILES = 400
SEVERITIES = ("high", "medium", "low")

# Scorecard checks worth naming when they score low.
KEY_CHECKS = {
    "Binary-Artifacts", "Branch-Protection", "Code-Review", "Dangerous-Workflow",
    "Maintained", "Pinned-Dependencies", "Security-Policy", "Signed-Releases",
    "Token-Permissions", "Vulnerabilities",
}

# ---------------------------------------------------------------------------
# Which files to scan

AGENT_FILENAMES = {
    "skill.md", "claude.md", "claude.local.md", "agents.md", "gemini.md",
    ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md",
}
AGENT_SUFFIXES = (".prompt.md", ".instructions.md", ".chatmode.md")
AGENT_DIRS = {
    "skills", "commands", "agents", "prompts",
    ".claude", ".claude-plugin", ".cursor", ".windsurf", ".clinerules", ".codex", ".gemini",
}
CONFIG_FILENAMES = {".mcp.json", "mcp.json", "hooks.json", "claude_desktop_config.json"}
CONFIG_DIRS = {".claude", ".claude-plugin", ".cursor", ".codex", ".gemini"}
SCRIPT_SUFFIXES = (".sh", ".bash", ".zsh", ".ps1", ".py", ".js", ".mjs", ".cjs", ".ts")
ROOT_SCRIPTS = {"install.sh", "setup.sh", "bootstrap.sh", "install.ps1", "get.sh"}
KIND_ORDER = ("license", "config", "agent", "workflow", "script", "readme")
LICENSE_FILE = re.compile(r"^(licen[cs]e|copying|unlicense)([-._][\w.-]*)?$")
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "testdata", "__fixtures__"}
TEST_FILE = re.compile(r"(\.|_)(test|spec)\.[a-z]+$|^test_.*\.py$")


def classify(path):
    """Return the kind of file this is for scanning, or None to skip it."""
    p = PurePosixPath(path)
    name = p.name.lower()
    dirs = [part.lower() for part in p.parts[:-1]]
    # Tests and fixtures quote attacks on purpose; agents don't load them.
    if TEST_DIRS.intersection(dirs) or TEST_FILE.search(name):
        return None
    if not dirs and LICENSE_FILE.match(name):
        return "license"
    if dirs[:2] == [".github", "workflows"] and name.endswith((".yml", ".yaml")):
        return "workflow"
    if name in CONFIG_FILENAMES or (name.endswith(".json") and CONFIG_DIRS.intersection(dirs)):
        return "config"
    if name in AGENT_FILENAMES or name.endswith(AGENT_SUFFIXES):
        return "agent"
    if name.endswith((".md", ".mdc", ".txt")) and AGENT_DIRS.intersection(dirs):
        return "agent"
    if name.endswith(SCRIPT_SUFFIXES) and ("hooks" in dirs or CONFIG_DIRS.intersection(dirs)):
        return "script"
    if not dirs and name in ROOT_SCRIPTS:
        return "script"
    if not dirs and name.startswith("readme"):
        return "readme"
    return None


def select_files(paths):
    """Pick the files to scan, most important kinds first, capped at MAX_FILES."""
    picked = [(KIND_ORDER.index(kind), path, kind)
              for path in paths if path for kind in [classify(path)] if kind]
    picked.sort()
    return [(path, kind) for _, path, kind in picked[:MAX_FILES]], len(picked) > MAX_FILES


# ---------------------------------------------------------------------------
# Rules. Each maps file kinds to a severity; kinds not listed are not checked.
# "high" means: review this before letting an agent use the repository.
# In the "quotable" kinds, a match inside quotes or after a negation ("never
# run ...") is usually an example of the attack, in docs or in a defense
# against it, so it only counts as low.

def rule(rule_id, title, pattern, severity, flags=re.IGNORECASE, quotable=()):
    return {"id": rule_id, "title": title, "re": re.compile(pattern, flags), "severity": severity,
            "quotable": quotable}


QUOTE_CHARS = "\"'“”‘’«»"
NEGATION = re.compile(r"\b(never|do not|don't|avoid|blocks?|blocked|forbid|prohibit|refuse|disallow|deny)\b"
                      r"|\b(attackers?|attacks?|malicious|e\.g\.|for example|such as|detects?|flags?)\b",
                      re.IGNORECASE)


def looks_like_example(line, m):
    before = line[:m.start()]
    prev = before.rstrip()[-1:]
    return (prev != "" and prev in QUOTE_CHARS) or before.count('"') % 2 == 1 or bool(NEGATION.search(before))


ALL_TEXT = ("agent", "config", "script", "readme", "workflow")

LINE_RULES = [
    rule("hidden-unicode-tags", "Invisible Unicode tag characters (text a model reads but people can't see)",
         "[\U000E0000-\U000E007F]", dict.fromkeys(ALL_TEXT, "high"), 0),
    rule("bidi-control", "Bidirectional control characters that can hide or reorder text",
         "[‪-‮⁦-⁩]",
         {"agent": "high", "config": "high", "script": "high", "workflow": "high", "readme": "medium"}, 0),
    rule("zero-width", "Zero-width characters inside text",
         "[​‌⁠᠎]|(?<=.)﻿",
         {"agent": "medium", "config": "medium", "script": "medium", "readme": "low"}, 0),
    rule("override-instructions", "Tells the model to ignore or override its instructions",
         r"\b(ignore|disregard|forget|override)\s+((all|any|the|your|of)\s+)*"
         r"(previous|prior|above|earlier|preceding|system|original|safety)\s+"
         r"(instructions?|prompts?|rules|guidelines|directives|messages)\b"
         r"|\b(disregard|override|bypass)\s+(your|the)\s+(system prompt|safety|guardrails)\b",
         {"agent": "high", "config": "high", "readme": "medium"}, quotable=ALL_TEXT),
    # Only hiding the agent's own actions or instructions; "never tell the user X is free" is an honesty rule.
    rule("conceal-from-user", "Tells the agent to hide what it does from the user",
         r"\b(do not|don't|never)\s+(tell|inform|notify|alert)\s+(the\s+|a\s+)?users?\s+(about|of)\s+"
         r"(this|these|it|that|what you|any of)\b"
         r"|\b(do not|don't|never)\s+(mention|reveal|disclose|show)\s+(this|these|it|that)\b[^.\n]{0,30}"
         r"\b(to|with)\s+the\s+user\b"
         r"|\b(hide|conceal)\s+(this|these|it|that|your actions?|what you)\b[^.\n]{0,20}\bfrom\s+the\s+user\b"
         r"|\bkeep\s+(this|these|it)\b[^.\n]{0,20}\b(hidden|secret)\s+from\s+the\s+user\b"
         r"|\b(run|execute|send|upload|post|install|delete|modify|change|commit|push)\b[^.\n]{0,40}"
         r"\bwithout\s+(telling|informing|notifying)\s+the\s+user\b"
         r"|\b(silently|secretly|covertly)\s+(run|execute|send|upload|post|install|delete|modify|exfiltrate)\b",
         {"agent": "high", "config": "high", "script": "medium", "readme": "medium"}, quotable=ALL_TEXT),
    rule("skip-confirmation", "Tells the agent to act without asking the user",
         r"\b(proceed|continue|go ahead|run|execute|apply|commit|push|merge|deploy|delete|install)\b[^.\n]{0,30}"
         r"\bwithout\s+(asking|confirmation|approval|permission|confirming)\b"
         r"|\b(do not|don't|never)\s+ask\s+(the\s+user\s+)?(for\s+)?(permission|confirmation|approval)\b",
         {"agent": "medium", "config": "medium"}, quotable=ALL_TEXT),
    rule("fake-chat-delimiters", "Fake chat or system-prompt delimiters",
         r"<\|im_(start|end)\|>|\[/?INST\]|<\|(system|assistant|user|endoftext)\|>|<\s*/\s*(system|instructions)\s*>",
         {"agent": "medium", "config": "medium", "readme": "low"}, quotable=ALL_TEXT),
    rule("secret-in-url", "URL that carries a secret from the environment, or command output",
         r"https?://[^\s\"'<>]*(\$\{?[A-Z_]*(TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|CREDENTIALS?)\b"
         r"|\$\((cat|env|printenv|base64|whoami|hostname)\b)",
         {"agent": "high", "config": "high", "script": "medium", "readme": "medium"}, 0),
    rule("secret-exfil", "Sends credential files over the network",
         r"\b(curl|wget|ncat|nc|scp|invoke-webrequest|iwr|invoke-restmethod|irm)\b[^\n]{0,150}"
         r"(\.ssh/|\bid_(rsa|dsa|ecdsa|ed25519)\b|\.aws/credentials|\.git-credentials|\.netrc\b|(\s|@|/)\.env\b)",
         {"agent": "high", "config": "high", "script": "high", "readme": "medium"}, quotable=("agent", "readme")),
    rule("secret-file-access", "Tells the agent to read credential files",
         r"\b(cat|type|read|open|copy|cp|upload)\b[^\n]{0,40}"
         r"(\.ssh/(id_|authorized_keys)|\.aws/credentials|\.git-credentials|\.netrc\b)",
         {"agent": "medium"}, quotable=ALL_TEXT),
    rule("pipe-to-shell", "Downloads code and runs it straight away",
         r"\b(curl|wget)\b[^\n|;]{0,300}\|\s*(sudo\s+)?(ba|z|da|k)?sh\b"
         r"|\b(iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,300}\|\s*iex\b|\binvoke-expression\b"
         r"|\beval\s+\"?\$\((curl|wget)\b",
         {"config": "high", "agent": "medium", "script": "medium", "readme": "low", "workflow": "low"},
         quotable=("agent", "readme", "script")),
    rule("base64-exec", "Decodes base64 and runs it",
         r"base64\s+(-d|--decode)\b[^\n]{0,200}\|\s*(sudo\s+)?(ba|z)?sh\b|frombase64string\([^\n]{0,200}\|\s*iex\b",
         {"agent": "high", "config": "high", "script": "high", "readme": "medium", "workflow": "medium"}),
    rule("reverse-shell", "Reverse shell pattern",
         r"/dev/tcp/[\w.-]+/\d+|\bnc(at)?\s+(-\w*\s+)*-\w*[ec]\b|\bsocat\b[^\n]{0,200}\bexec:",
         dict.fromkeys(ALL_TEXT, "high")),
    rule("destructive-command", "Destructive command (wipes files or disks)",
         r"\brm\s+-(rf|fr)\s+(/|~|\$HOME)(\s|$|\")|\bmkfs\.\w+\s+/dev/|\bdd\s+if=/dev/(zero|u?random)\s+of=/dev/",
         {"config": "high", "script": "high", "agent": "medium", "readme": "medium", "workflow": "medium"},
         quotable=("agent", "readme", "script")),
    rule("long-base64", "Long base64 blob (hidden payload?)",
         r"[A-Za-z0-9+/]{240,}={0,2}", {"agent": "medium", "config": "medium"}, 0),
    rule("bypass-permissions", "Turns off the agent's permission checks",
         r"bypassPermissions|dangerously[-_]?skip[-_]?permissions|\"(autoApprove|alwaysAllow)\"\s*:"
         r"|enableAllProjectMcpServers\"?\s*:\s*true|approval[_-]?policy\s*=\s*\"?never|--yolo\b",
         {"config": "high", "script": "medium", "agent": "low", "readme": "low"}, quotable=("script",)),
    rule("hook-network", "Hook or config command that talks to the network",
         r"\"command\"\s*:\s*\"[^\"]*\b(curl|wget|nc|ncat|invoke-webrequest|iwr)\b", {"config": "high"}),
    rule("mcp-runs-package", "MCP server that downloads and runs a package on start",
         r"\"command\"\s*:\s*\"(npx|uvx|bunx|pipx|dlx)\"", {"config": "low"}),
    rule("workflow-write-all", "Workflow token has write access to everything",
         r"permissions\s*:\s*write-all", {"workflow": "medium"}),
]

# Rules whose match inside a hidden HTML comment makes the comment dangerous.
DANGER_RES = [r["re"] for r in LINE_RULES if r["id"] in {
    "override-instructions", "conceal-from-user", "secret-in-url", "secret-exfil", "secret-file-access",
    "pipe-to-shell", "base64-exec", "reverse-shell", "destructive-command", "bypass-permissions"}]

# Findings are reported in two groups: prompt injection (text that steers an AI)
# and security (code, settings and workflows that can do harm). Unlisted rules are security.
INJECTION_RULES = {
    "hidden-unicode-tags", "bidi-control", "zero-width", "override-instructions", "conceal-from-user",
    "skip-confirmation", "fake-chat-delimiters", "long-base64", "hidden-comment-instructions",
    "ci-agent-untrusted-input",
}
CATEGORIES = ("security", "injection")
SECURITY_POLICY_FILES = {"security.md", ".github/security.md", "docs/security.md"}

UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)"
    r"|comment\.body|review\.body|review_comment\.body|head_commit\.(message|author\.(name|email))"
    r"|commits\b[^}]*\.(message|author)|discussion\.(title|body)|pages\b[^}]*\.page_name)|github\.head_ref)")
# run: steps, and script: inputs of actions/github-script, are code.
RUN_LINE = re.compile(r"^(\s*)(-\s+)?(run|script)\s*:\s*(.*)$")
HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)
COMMENT_ADDRESSED = re.compile(
    r"\b(note|instructions?|message|reminder)s?\s+(to|for)\s+(the\s+)?"
    r"(ai|assistant|agent|model|llm|claude|chatgpt|copilot|cursor)\b"
    r"|\b(ai|assistant|agent|claude|chatgpt|copilot|llm)s?\s*[:,]\s+\S"
    r"|\bignore\s+(all|previous|the above)\b|\byou\s+(must|should|are now)\b|\bsystem prompt\b",
    re.IGNORECASE)
WILDCARD_ALLOW = re.compile(r"\"allow\"\s*:\s*\[[^\]]*\"(Bash|Bash\(\*\)|Bash\(:?\*:?\*?\)|\*)\"", re.DOTALL)
PR_TARGET = re.compile(r"^\s*(on\s*:.*\b)?pull_request_target\b", re.MULTILINE)
HEAD_CHECKOUT = re.compile(
    r"ref\s*:\s*\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref)"
    r"|refs/pull/\$\{\{[^}]*\}\}/(head|merge)")
AGENT_ACTION = re.compile(
    r"uses\s*:\s*[\w.-]*/[\w.-]*(claude|codex|gemini|copilot|openhands|aider|cursor)[\w.-]*@", re.IGNORECASE)
UNTRUSTED_TRIGGER = re.compile(
    r"^\s*(-\s*)?(issues|issue_comment|pull_request_target|pull_request_review_comment"
    r"|discussion|discussion_comment)\s*:?\s*$|^\s*on\s*:.*\b(issues|issue_comment|pull_request_target)\b",
    re.MULTILINE)


def line_of(text, index):
    return text.count("\n", 0, index) + 1


def scan_text(text, kind):
    """Yield (rule_id, title, severity, line_number, source, match) for one file's text.

    match offsets are relative to source; match is None when source is the matched text itself.
    """
    lines = text.splitlines()
    for r in LINE_RULES:
        severity = r["severity"].get(kind)
        if not severity:
            continue
        for number, line in enumerate(lines, 1):
            m = r["re"].search(line)
            if m:
                example = kind in r["quotable"] and looks_like_example(line, m)
                yield r["id"], r["title"], "low" if example else severity, number, line, m

    if kind in ("agent", "readme"):
        for m in HTML_COMMENT.finditer(text):
            inner = m.group(1)
            if any(d.search(inner) for d in DANGER_RES):
                severity = "high" if kind == "agent" else "medium"
            elif COMMENT_ADDRESSED.search(inner):
                severity = "low"
            else:
                continue
            yield ("hidden-comment-instructions", "HTML comment (hidden when rendered) with instructions for an AI",
                   severity, line_of(text, m.start()), m.group(0), None)

    if kind == "config":
        m = WILDCARD_ALLOW.search(text)
        if m:
            yield ("wildcard-allow", "Pre-approves any shell command for the agent", "high",
                   line_of(text, m.start()), m.group(0), None)

    if kind == "workflow":
        yield from scan_workflow(text, lines)


def scan_workflow(text, lines):
    code_indent = None
    for number, line in enumerate(lines, 1):
        m = RUN_LINE.match(line)
        if m:
            code_indent = len(m.group(1)) + len(m.group(2) or "")
            body = m.group(4)
        elif code_indent is not None and (not line.strip() or len(line) - len(line.lstrip()) > code_indent):
            body = line
        else:
            code_indent = None
            continue
        e = UNTRUSTED_EXPR.search(body)
        if e:
            yield ("workflow-script-injection", "Workflow pastes untrusted issue or PR text into code it runs",
                   "high", number, body, e)
    if PR_TARGET.search(text):
        m = HEAD_CHECKOUT.search(text)
        if m:
            yield ("pwn-request", "pull_request_target workflow checks out and may run untrusted PR code",
                   "high", line_of(text, m.start()), m.group(0), None)
    a = AGENT_ACTION.search(text)
    if a and UNTRUSTED_TRIGGER.search(text):
        yield ("ci-agent-untrusted-input", "AI agent in CI runs on issues or PRs anyone can write (prompt injection)",
               "medium", line_of(text, a.start()), a.group(0), None)


def excerpt(text, match=None, width=80):
    """A short, escaped excerpt: invisible and control characters become \\u{XXXX}."""
    if match is not None and len(text) > width:
        start = max(0, match.start() - 20)
        text = text[start:start + width]
    out = []
    for ch in text.strip():
        code = ord(ch)
        if ch == " " or (ch.isprintable() and not 0x200B <= code <= 0x206F and not 0xE0000 <= code <= 0xE007F
                         and code != 0xFEFF):
            out.append(ch)
        else:
            out.append("\\u{%X}" % code)
    s = "".join(out)
    return s if len(s) <= width else s[:width - 1] + "…"


def scan_tree(root, files, snippets=False):
    """Scan the selected (path, kind) files under root. Returns a list of findings."""
    grouped = {}
    for rel, kind in files:
        full = os.path.join(root, *PurePosixPath(rel).parts)
        try:
            if os.path.islink(full) or not os.path.isfile(full) or os.path.getsize(full) > MAX_FILE_BYTES:
                continue
            with open(full, "rb") as f:
                data = f.read()
        except OSError:
            continue
        if b"\0" in data[:8192]:
            continue
        text = data.decode("utf-8", errors="replace")
        for rule_id, title, severity, number, line, m in scan_text(text, kind):
            finding = grouped.get((rule_id, rel))
            if finding is None:
                category = "injection" if rule_id in INJECTION_RULES else "security"
                # File names come from the scanned repository too, so escape them like excerpts.
                finding = grouped[(rule_id, rel)] = {"category": category, "severity": severity, "rule": rule_id,
                                                     "title": title, "file": excerpt(rel, width=120),
                                                     "line": number, "count": 0}
            finding["count"] += 1
            # Keep the worst occurrence: a quoted example may come before the real thing.
            if finding["count"] == 1 or SEVERITIES.index(severity) < SEVERITIES.index(finding["severity"]):
                finding.update(severity=severity, line=number)
                if snippets:
                    finding["excerpt"] = excerpt(line, m)
    findings = list(grouped.values())
    findings.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["file"], f["line"]))
    return findings


# ---------------------------------------------------------------------------
# Fetching

def run_git(args, cwd=None, timeout=120, stdin=None):
    # Never prompt for credentials, never write symlinks, skip Git LFS downloads.
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_LFS_SKIP_SMUDGE="1", GCM_INTERACTIVE="never")
    safe = ["-c", "core.symlinks=false", "-c", "filter.lfs.required=false", "-c", "protocol.file.allow=never",
            "--literal-pathspecs"]
    proc = subprocess.run(["git", *safe, *args], cwd=cwd, input=stdin, capture_output=True,
                          timeout=timeout, env=env)
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        raise RuntimeError(msg[-1] if msg else "git %s failed" % args[0])
    return proc.stdout


def fetch_remote(slug, dest, timeout):
    """Partial-clone slug into dest and check out only the files worth scanning."""
    run_git(["clone", "--quiet", "--depth", "1", "--filter=blob:none", "--no-checkout",
             "--", "https://github.com/%s.git" % slug, dest], timeout=timeout)
    listing = run_git(["ls-tree", "-r", "-z", "HEAD"], cwd=dest, timeout=timeout)
    blobs = {}
    for entry in listing.decode("utf-8", "replace").split("\0"):
        meta, _, path = entry.partition("\t")
        fields = meta.split()
        if len(fields) == 3 and fields[1] == "blob":
            blobs[path] = fields[2]
    files, truncated = select_files(list(blobs))
    if files:
        # Fetch all selected blobs in one request, as git's own lazy fetch does; a plain
        # checkout would fetch them one round trip at a time.
        oids = "".join(blobs[path] + "\n" for path, _ in files).encode("ascii")
        try:
            run_git(["-c", "fetch.negotiationAlgorithm=noop", "fetch", "--quiet", "--no-tags",
                     "--no-write-fetch-head", "--recurse-submodules=no", "--filter=blob:none", "--stdin",
                     "origin"], cwd=dest, timeout=timeout, stdin=oids)
        except RuntimeError:
            pass  # older git: the checkout below fetches lazily instead
        spec = "\0".join(path for path, _ in files).encode("utf-8") + b"\0"
        run_git(["checkout", "HEAD", "--pathspec-from-file=-", "--pathspec-file-nul"],
                cwd=dest, timeout=timeout, stdin=spec)
    return list(blobs), files, truncated


def list_local(root):
    try:
        out = run_git(["ls-files", "-z"], cwd=root, timeout=60)
        return out.decode("utf-8", "replace").split("\0")
    except (RuntimeError, OSError, subprocess.SubprocessError):
        paths = []
        for base, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d != ".git"]
            for name in filenames:
                paths.append(os.path.relpath(os.path.join(base, name), root).replace(os.sep, "/"))
        return paths


def slug_from_checkout(root):
    try:
        url = run_git(["remote", "get-url", "origin"], cwd=root, timeout=30).decode().strip()
    except (RuntimeError, OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"github\.com[:/]([^/]+/[^/]+?)(\.git)?/?$", url)
    return m.group(1) if m and SLUG_RE.match(m.group(1)) else None


def scorecard(slug, timeout):
    req = urllib.request.Request(SCORECARD_API.format(slug), headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"status": "not scored"}
        return {"status": "error", "error": "HTTP %d" % e.code}
    except (urllib.error.URLError, OSError, ValueError) as e:
        return {"status": "error", "error": str(getattr(e, "reason", e))}
    date = str(data.get("date", ""))[:10]
    try:
        age = (datetime.date.today() - datetime.date.fromisoformat(date)).days
    except ValueError:
        age = None
    low = sorted((c.get("score", -1), c.get("name")) for c in data.get("checks", [])
                 if c.get("name") in KEY_CHECKS and 0 <= c.get("score", -1) < 5)
    return {"status": "ok", "score": data.get("score"), "date": date, "age_days": age,
            "weak_checks": ["%s %s" % (name, score) for score, name in low]}


def remove_tree(path):
    # git marks pack files read-only, which stops rmtree on Windows.
    def make_writable(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=make_writable)
    else:
        shutil.rmtree(path, onerror=make_writable)


def safe_check(target, local, args):
    try:
        return check(target, local, args)
    except Exception as e:  # one broken repository must not stop the others
        return {"repo": target, "error": "%s: %s" % (type(e).__name__, e)}


def check(target, local, args):
    slug = slug_from_checkout(target) if local else target
    result = {"repo": slug or target}
    if not local and not SLUG_RE.match(target):
        result["error"] = "not a GitHub owner/name"
        return result
    result["scorecard"] = scorecard(slug, args.timeout) if slug and not args.no_scorecard \
        else {"status": "skipped"}
    tmp = None
    try:
        if local:
            root = target
            paths = list_local(root)
            files, truncated = select_files(paths)
        else:
            tmp = tempfile.mkdtemp(prefix="trend-minions-scan-")
            root = os.path.join(tmp, "repo")
            paths, files, truncated = fetch_remote(slug, root, args.timeout)
        findings = scan_tree(root, files, args.snippets)
        result["license"] = detect_license(root, [path for path, kind in files if kind == "license"])
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        result["error"] = "could not fetch: %s" % e
        return result
    finally:
        if tmp:
            remove_tree(tmp)
    result["files_scanned"] = sum(1 for _, kind in files if kind != "license")
    result["truncated"] = truncated
    result["security_policy"] = any(p.lower() in SECURITY_POLICY_FILES for p in paths)
    for category in CATEGORIES:
        found = [f for f in findings if f["category"] == category]
        counts = {s: sum(1 for f in found if f["severity"] == s) for s in SEVERITIES}
        result[category] = {"risk": next((s for s in SEVERITIES if counts[s]), "none"),
                            "percent": risk_percent(counts), "counts": counts,
                            "findings": found[:args.max_findings],
                            "more_findings": max(0, len(found) - args.max_findings)}
    return result


# Each risk level owns a band, so the percentage never contradicts the level.
PERCENT_BANDS = {"high": (60, 100), "medium": (25, 59), "low": (5, 24)}


def risk_percent(counts):
    """A 0-100 risk score: 0 with no findings, else inside the band of the worst level.

    One finding at the worst level sits at the bottom of the band; each further one moves it
    up with diminishing steps. Findings one and two levels lower count 0.3 and 0.1. It is a
    score for comparing repos, not a probability that a repo is malicious.
    """
    levels = [s for s in SEVERITIES if counts[s]]
    if not levels:
        return 0
    top = SEVERITIES.index(levels[0])
    weighted = sum(counts[s] * w for s, w in zip(SEVERITIES[top:], (1, 0.3, 0.1)))
    low, high = PERCENT_BANDS[SEVERITIES[top]]
    return round(low + (high - low) * (1 - 0.7 ** (weighted - 1)))


# ---------------------------------------------------------------------------
# License: whether the repository may be used at work. commercial_use is True for open-source
# licenses, "restricted" for source-available ones with conditions on commercial use, False for
# non-commercial licenses or no license at all (all rights reserved), None when unrecognised.
# Checked in order: source-available licenses first (BUSL names its future open-source
# license), then open-source ones (GPLv2 itself mentions "noncommercial distribution"), and
# non-commercial terms last. GNU licenses are named by the title at the top, since their texts
# mention one another (GPLv2 ends by recommending the Library GPL).

LICENSES = [
    ("BUSL-1.1", r"Business Source License", "restricted"),
    ("SSPL-1.0", r"Server Side Public License", "restricted"),
    ("Elastic-2.0", r"\bElastic License\b", "restricted"),
    ("AGPL", r"\A[\s\S]{0,300}GNU AFFERO GENERAL PUBLIC LICENSE", True),
    ("LGPL", r"\A[\s\S]{0,300}GNU (LESSER|LIBRARY) GENERAL PUBLIC LICENSE", True),
    ("GPL", r"\A[\s\S]{0,300}GNU GENERAL PUBLIC LICENSE", True),
    ("MPL-2.0", r"Mozilla Public License", True),
    ("EPL-2.0", r"Eclipse Public License", True),
    ("Apache-2.0", r"Apache License,?\s+Version 2\.0", True),
    ("MIT", r"Permission is hereby granted, free of charge", True),
    ("ISC", r"Permission to use, copy, modify, and(/or)? distribute this software for any\s+purpose", True),
    ("BSD-3-Clause", r"Redistribution and use in source and binary forms[\s\S]*Neither the name", True),
    ("BSD-2-Clause", r"Redistribution and use in source and binary forms", True),
    ("Unlicense", r"free and unencumbered software released into the public domain", True),
    ("CC0-1.0", r"\bCC0 1\.0\b|Creative Commons Zero", True),
    ("CC-BY-4.0", r"Attribution(-ShareAlike)? 4\.0 International", True),
    ("BSL-1.0", r"Boost Software License", True),
    ("Zlib", r"This software is provided ['‘]as-is['’], without any express or implied", True),
    ("Non-commercial", r"\bnon-?commercial\b|\bBY-NC\b|personal use only|not for commercial use", False),
]
LICENSES = [(spdx, re.compile(pattern, re.IGNORECASE), use) for spdx, pattern, use in LICENSES]


def classify_license(text):
    for spdx, pattern, use in LICENSES:
        if pattern.search(text):
            if spdx in ("AGPL", "LGPL", "GPL"):
                version = re.search(r"Version (\d)(\.\d)?", text)
                if version:
                    spdx += "-%s%s" % (version.group(1), version.group(2) or ".0")
            return spdx, use
    return "unknown", None


def detect_license(root, license_files):
    """Classify the repository's root license files. Several (MIT plus Apache-2.0) mean a choice."""
    found = []
    for rel in license_files:
        full = os.path.join(root, rel)
        try:
            if os.path.islink(full) or os.path.getsize(full) > MAX_FILE_BYTES:
                continue
            with open(full, "rb") as f:
                text = f.read().decode("utf-8", errors="replace")
        except OSError:
            continue
        found.append(classify_license(text))
    if not found:
        return {"ids": [], "commercial_use": False, "note": "no license file: all rights reserved"}
    uses = [use for _, use in found]
    for best in (True, "restricted", False):
        if best in uses:
            use = best
            break
    else:
        use = None
    return {"ids": sorted({spdx for spdx, _ in found}), "commercial_use": use}


# ---------------------------------------------------------------------------
# Output

def format_text(results):
    lines = []
    for r in results:
        head = r["repo"]
        if "error" in r:
            lines.append("%s  ERROR %s" % (head, r["error"]))
            continue
        sc = r["scorecard"]
        if sc["status"] == "ok":
            score = "Scorecard %s/10 (%s)" % (sc["score"], sc["date"])
            if sc["weak_checks"]:
                score += " weak: " + ", ".join(sc["weak_checks"])
        else:
            score = "Scorecard " + sc["status"] + (": " + sc["error"] if sc.get("error") else "")
        lic = r["license"]
        lines.append("%s  %s  SECURITY.md: %s  License: %s (commercial use: %s)  (%d files scanned%s)" % (
            head, score, "yes" if r["security_policy"] else "no", " OR ".join(lic["ids"]) or "none",
            {True: "yes", False: "no", "restricted": "restricted", None: "unknown"}[lic["commercial_use"]],
            r["files_scanned"], ", capped" if r["truncated"] else ""))
        for category, label in (("security", "Security"), ("injection", "Prompt injection")):
            group = r[category]
            c = group["counts"]
            lines.append("  %s risk: %s %d%% (%d high, %d medium, %d low)" % (
                label, group["risk"], group["percent"], c["high"], c["medium"], c["low"]))
            for f in group["findings"]:
                lines.append("    %-6s %-28s %s:%d%s  %s" % (
                    f["severity"], f["rule"], f["file"], f["line"],
                    " (x%d)" % f["count"] if f["count"] > 1 else "", f["title"]))
                if "excerpt" in f:
                    lines.append("           > " + f["excerpt"])
            if group["more_findings"]:
                lines.append("    … %d more" % group["more_findings"])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("repos", nargs="*", help="GitHub repositories as owner/name")
    parser.add_argument("--path", action="append", default=[], help="scan a local checkout (repeatable)")
    parser.add_argument("--format", choices=("json", "text"), default="json")
    parser.add_argument("--snippets", action="store_true", help="include short escaped excerpts")
    parser.add_argument("--max-findings", type=int, default=3,
                        help="findings listed per repo and group (default 3)")
    parser.add_argument("--jobs", type=int, default=6, help="repositories checked in parallel (default 6)")
    parser.add_argument("--timeout", type=int, default=120, help="seconds per network step (default 120)")
    parser.add_argument("--no-scorecard", action="store_true", help="skip the OpenSSF Scorecard lookup")
    args = parser.parse_args(argv)
    targets = [(r, False) for r in args.repos] + [(p, True) for p in args.path]
    if not targets:
        parser.error("give at least one owner/name or --path")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        results = list(pool.map(lambda t: safe_check(t[0], t[1], args), targets))
    if args.format == "json":
        json.dump(results, sys.stdout, separators=(",", ":"), ensure_ascii=True)
        sys.stdout.write("\n")
    else:
        sys.stdout.write(format_text(results) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
