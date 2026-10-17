# Trend Minions

See what's trending on GitHub right now, and how safe each repo is to use with an AI agent.

Install it:

```
/plugin install trend-minions --marketplace vfreibaer/somefun
```

Then ask "what's trending on GitHub this week?" or run the skill directly:

```
/trend-minions:trending
/trend-minions:trending weekly rust
/trend-minions:trending claude skills
/trend-minions:trending monthly python developers
```

You get the trending repos (or developers) for today, this week or this month, for one language or a topic such as "claude skills", plus a short read on the themes behind them. Every repo in the table gets three checks:

- **Security** and **Prompt injection**: a banana with a risk score: ![green banana](assets/banana-green.svg) green for 0–24%, ![yellow banana](assets/banana-yellow.svg) yellow for 25–59%, ![red banana](assets/banana-red.svg) red for 60–100%. The score rises with the number and severity of findings; it's for comparing repos, not a probability that one is malicious. Where images can't be shown, such as in a terminal, you see 🟢🍌, 🟡🍌 or 🔴🍌 instead.
- **Safe for work (EU)**: ✅ Yes or ⛔ No. Yes only when the repo's license allows use at work and its description isn't aimed at adult content, piracy or getting around copy protection, cheats, malware, collecting personal data or surveillance (GDPR), or practices the EU AI Act prohibits. It's a quick check, not legal advice.

Say `no-scan` to get just the list.

## What it checks

A bundled Python script, `skills/trending/scripts/scan_repos.py`, does the checks. It looks at the files AI agents read and run (skills, `CLAUDE.md` and `AGENTS.md`, hooks, agent and MCP settings, the README, install scripts) and the repo's GitHub Actions workflows:

- **Security**: workflows that put untrusted PR or issue text into commands, settings or hooks that pre-approve any shell command or turn off permission checks, credentials sent over the network, downloaded scripts piped into a shell, reverse shells, destructive commands. It also reports the [OpenSSF Scorecard](https://scorecard.dev) score where one exists, whether the repo has a `SECURITY.md`, and the repo's license.
- **Prompt injection**: hidden Unicode, hidden HTML comments with instructions for an AI, text telling the model to ignore its instructions, hide things from the user or act without asking, fake chat delimiters, AI agents in CI that read issues anyone can write.

The script contains detection patterns for these attacks, such as the text of a reverse shell, so it can recognise them. It never runs code from the repos it scans. It's a pattern scan, not an audit: a red banana means "review before using this with an agent", not proof of bad intent.

## What it fetches and sends

Everything the plugin does over the network:

- **GitHub Trending pages**: Claude fetches `https://github.com/trending` pages (for a language or topic, a few of them) to read the list.
- **The listed repositories**: for each repo on the list, the script runs `git clone` from `https://github.com/<owner>/<name>.git` as a partial clone into a temporary folder, fetches only the files listed above, reads them, and deletes the folder. Git runs without credential prompts, without symlinks and without Git LFS downloads.
- **OpenSSF Scorecard**: for each repo, the script asks `https://api.securityscorecards.dev/projects/github.com/<owner>/<name>` for its score. The repo name is the only data sent.
- **Banana images**: the answer embeds the three banana pictures from this plugin's `assets` folder as images hosted at `raw.githubusercontent.com/vfreibaer/somefun`. The app that displays Claude's answer loads them from there, like any image on a web page; the plugin itself sends nothing with that request.

The plugin reads no credentials, sends nothing else anywhere, and writes nothing outside the temporary folder. The script prints only rule names, file names and line numbers, never file contents, so text from the scanned repos doesn't reach Claude.

## Requirements

Python 3.8 or later and git 2.25 or later on the machine that runs the skill, and network access to github.com and api.securityscorecards.dev. Without them the skill still shows the trending list and marks the checks n/a.

## License

MIT. See [LICENSE](LICENSE).
