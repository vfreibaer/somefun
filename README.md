# somefun

Small, fun [Claude Code](https://claude.com/claude-code) plugins. This repo is a plugin marketplace.

## Plugins

### 🍌 Trend Minions (`trend-minions`)

Shows what's trending on GitHub right now: the top repos (or developers) for today, this week or this month, optionally for one language or a topic such as "claude skills", plus a short read on the themes behind them. GitHub Trending has no topic filter, so for a topic the skill merges the trending pages for all languages and the languages where tools usually trend, keeps the repos whose name or description matches, and sorts them by stars gained.

Every repo in the table gets a **Security** and a **Prompt injection** banana badge with a risk score, 🟢🍌 0–24%, 🟡🍌 25–59% or 🔴🍌 60–100%, and a **Safe for work (EU)** ✅ Yes or ⛔ No. A bundled scanner checks the files AI agents read and run and the repo's workflows, and never prints their contents. [The plugin's README](plugins/trend-minions/README.md) explains every check and everything the plugin fetches.

Install it:

```
/plugin install trend-minions --marketplace vfreibaer/somefun
```

On Claude Code versions before 2.1.275, add the marketplace first:

```
/plugin marketplace add vfreibaer/somefun
/plugin install trend-minions@somefun
```

Use it by asking, for example "what's trending on GitHub this week?", or call the skill directly:

```
/trend-minions:trending
/trend-minions:trending weekly rust
/trend-minions:trending weekly claude skills
/trend-minions:trending monthly python developers
```

The plugin used to be called `github-trending`. If you installed it under that name, run `/plugin marketplace update somefun`, then `/plugin install trend-minions@somefun` once. Claude Code moves your settings from the old name to the new one by itself.

You can also run the scanner on its own, on any repo or local checkout:

```
python3 plugins/trend-minions/skills/trending/scripts/scan_repos.py --format text owner/name
python3 plugins/trend-minions/skills/trending/scripts/scan_repos.py --format text --snippets --path ./some-checkout
```

`--snippets` adds short excerpts (invisible characters escaped) for human review.

## Try a plugin without installing it

```
claude --plugin-dir ./plugins/trend-minions
```

## Tests

```
python3 -m unittest discover -s tests
```

## License

MIT. See [LICENSE](LICENSE).
