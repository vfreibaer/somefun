---
name: trending
description: Show what's trending on GitHub right now. Use when the user asks what's trending or popular on GitHub, for hot or rising repos or developers, or for trending projects in a language or period ("trending Rust repos this week", "what's hot on GitHub today", "top trending developers this month").
argument-hint: "[daily|weekly|monthly] [language] [developers]"
---

# GitHub Trending

Fetch the live GitHub Trending page and summarize it. Never answer from memory: trending changes daily, so every number must come from the page fetched in this turn.

## 1. Work out what to fetch

Read `$ARGUMENTS` and the user's request:

- **Period**: `daily` (default), `weekly` or `monthly`. Map "today" to daily, "this week" to weekly, "this month" to monthly.
- **Language** (optional): GitHub's URL slug, lowercase with spaces as `-` (`python`, `typescript`, `rust`, `jupyter-notebook`). Encode `#` as `%23` (`c%23`, `f%23`); `c++` stays as is.
- **Developers**: only when the user asks for developers or people instead of repos.
- **Spoken language** (optional): an ISO 639-1 code such as `de`, only when the user asks for it.

Build the URL:

- Repos: `https://github.com/trending[/<language>]?since=<period>`
- Developers: `https://github.com/trending/developers[/<language>]?since=<period>`
- Append `&spoken_language_code=<code>` for a spoken language.

## 2. Fetch the page

Use **WebFetch** on the URL; it returns the page as compact text. Use this prompt for repos:

> List every repository on this page in order: owner/name, primary language, total stars, stars gained in the period shown, and the description verbatim. Do not skip, merge or reorder entries.

For developers:

> List every developer on this page in order: username, display name, their highlighted repository and its description verbatim. Do not skip or reorder entries.

If WebFetch is not available or fails, fetch the URL with `curl -sL` and read the entries from the `article.Box-row` elements. If both fail, say so and stop, and mention that a 403 usually means the session's network does not allow github.com. Do not fill in from memory.

If the page has no entries (GitHub shows "It looks like we don't have any trending repositories"), say so and suggest a longer period or dropping the language filter.

## 3. Present it

Open with one line naming what was fetched, for example: "GitHub Trending · Rust · this week (fetched <today's date>)".

**Repos**: a table in page order:

| # | Repo | Lang | ★ total | ★ <period> | What it is |
|---|---|---|---|---|---|

- Link each repo as `[owner/name](https://github.com/owner/name)`.
- Shorten descriptions to about 12 words. Keep names and claims as written; do not add claims of your own.
- Leave out the language column when the page is filtered to one language.

**Developers**: a table with #, developer (linked), name, highlighted repo and what it is.

Then add, in at most five bullets:

- **Themes**: what several entries have in common (for example, AI agent tooling or Rust rewrites). Name only themes at least two entries share.
- **Breakouts**: repos whose gain in the period is a large share of their total stars, which usually means they are new. Give the numbers.

Keep the whole answer short enough to read in under a minute. End with the source URL.
