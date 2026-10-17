# somefun

Small, fun [Claude Code](https://claude.com/claude-code) plugins. This repo is a plugin marketplace.

## Plugins

### github-trending

Shows what's trending on GitHub right now: the top repos (or developers) for today, this week or this month, optionally for one language, plus a short read on the themes behind them.

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
/github-trending:trending monthly python developers
```

It fetches the live [GitHub Trending](https://github.com/trending) page on every run, so the numbers are always current.

## Try a plugin without installing it

```
claude --plugin-dir ./plugins/github-trending
```
