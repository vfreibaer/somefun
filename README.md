# somefun

Small, fun [Claude Code](https://claude.com/claude-code) plugins. This repo is a plugin marketplace.

## Plugins

### github-trending

Shows what's trending on GitHub right now: the top repos (or developers) for today, this week or this month, optionally for one language or a topic such as "claude skills", plus a short read on the themes behind them. GitHub Trending has no topic filter, so for a topic the skill merges the trending pages for all languages and the languages where tools usually trend, keeps the repos whose name or description matches, and sorts them by stars gained.

Every repo it lists also gets a **security** and a **prompt-injection** rating (High, Medium, Low or None) with a risk score in percent, shown as a traffic light: 🟢 0–24%, 🟡 25–59%, 🔴 60–100%, such as "🟡 34%". The score always stays inside its level's band (None 0%, Low 5–24%, Medium 25–59%, High 60–100%) and rises with the number of findings; it's for comparing repos, not a probability that one is malicious. A bundled scanner checks the files AI agents read and run (skills, `CLAUDE.md`/`AGENTS.md`, hooks, agent and MCP settings, the README, install scripts) and the repo's GitHub Actions workflows:

- **Security**: workflows that put untrusted PR or issue text into commands, settings or hooks that pre-approve any shell command or turn off permission checks, credentials sent over the network, downloaded scripts piped into a shell, reverse shells, destructive commands. Also shows the [OpenSSF Scorecard](https://scorecard.dev) score where one exists, and whether there is a `SECURITY.md`.
- **Prompt injection**: hidden Unicode, hidden HTML comments with instructions for an AI, text telling the model to ignore its instructions, hide things from the user or act without asking, fake chat delimiters, AI agents in CI that read issues anyone can write.

A **Safe for work (EU)** column says ✅ Yes or ⛔ No: Yes only when the repo's license allows use at work (an open-source license; no license, non-commercial and source-available licenses are No) and its description isn't aimed at adult content, piracy or getting around copy protection and terms of service, cheats, malware, collecting personal data or surveillance (GDPR), or practices the EU AI Act prohibits. Every No comes with its reason. It's a quick check, not legal advice.

The table lists Security, Prompt injection and Safe for work (EU) first, then language, stars and description.

The scanner downloads only those files (a git partial clone), takes about 10 to 30 seconds for a full trending page, and never prints file contents, so untrusted text doesn't reach the agent. It's a pattern scan, not an audit: High means "review before using this with an agent", not proof of bad intent. It needs Python 3.8+ and git 2.25+. Say `no-scan` to get just the list.

Install it:

```
/plugin install github-trending --marketplace vfreibaer/somefun
```

On Claude Code versions before 2.1.275, add the marketplace first:

```
/plugin marketplace add vfreibaer/somefun
/plugin install github-trending@somefun
```

Use it by asking, for example "what's trending on GitHub this week?", or call the skill directly:

```
/github-trending:trending
/github-trending:trending weekly rust
/github-trending:trending weekly claude skills
/github-trending:trending monthly python developers
```

It fetches the live [GitHub Trending](https://github.com/trending) page on every run, so the numbers are always current.

You can also run the scanner on its own, on any repo or local checkout:

```
python3 plugins/github-trending/skills/trending/scripts/scan_repos.py --format text owner/name
python3 plugins/github-trending/skills/trending/scripts/scan_repos.py --format text --snippets --path ./some-checkout
```

`--snippets` adds short excerpts (invisible characters escaped) for human review.

## Try a plugin without installing it

```
claude --plugin-dir ./plugins/github-trending
```

## Tests

```
python3 -m unittest discover -s plugins/github-trending/tests
```
