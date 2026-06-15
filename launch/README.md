# Launch drafts

**These are drafts for review — nothing here has been posted anywhere.** No links
have been submitted to Hacker News, Reddit, dev.to, or any other site.

All drafts lead with the **enforcement-moat** angle (argument-level tool firewall,
tamper-evident audit log, trust provenance, kill switch) and use the **benchmark
numbers as the hook** — including the unflattering ones, per the project's honesty
rules. Numbers are quoted from `benchmarks/results/latest.json`; re-verify they
still match before posting.

| File | Channel | Notes |
|------|---------|-------|
| `show-hn.md` | Hacker News (Show HN) | Title options + body + prepared answers to likely questions |
| `reddit-langchain.md` | r/LangChain | LangGraph-first framing, asks for specific feedback |
| `devto-teardown.md` | dev.to | Design teardown of the architecture + benchmark |
| `good-first-issues/` | GitHub issues | 3 ready-to-paste, scoped contributor tickets |

## Before posting (human checklist)

- [ ] Re-run `python benchmarks/run.py` and confirm the quoted numbers still hold.
- [ ] Confirm the repo is public and the README renders.
- [ ] Decide on a title from the options in `show-hn.md`.
- [ ] Post the "good first issue" tickets as real GitHub issues and label them so
      the launch posts can point contributors at them.
- [ ] Be available to answer comments for the first few hours.
