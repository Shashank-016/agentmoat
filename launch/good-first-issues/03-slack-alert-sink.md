# good first issue: Add a Slack alert sink for critical security events

**Labels:** `good first issue`, `integrations`, `help wanted`

## Background

AgentMoat emits `SecurityEvent`s onto an `EventBus` that already supports
subscribers, but there's no built-in way to push critical events (policy
violations, kill-switch trips, engine errors) to an on-call channel. A Slack sink
is a small, well-bounded first integration — and it's on the roadmap
("Slack / PagerDuty alert sinks").

## What to do

1. Look at how subscribers attach to the bus in `agentmoat/bus.py` (the `subscribe`
   mechanism) and the `SecurityEvent` shape in `agentmoat/events.py`
   (`severity`, `event_type`, `flags`, `payload`).
2. Add a small `SlackAlertSink` (suggested home: `agentmoat/sinks/slack.py`, a new
   subpackage) that:
   - takes a webhook URL (read from an env var like `AGENTMOAT_SLACK_WEBHOOK`, not
     hard-coded),
   - filters to `severity == "critical"` by default (configurable),
   - posts a concise message (session, agent, event type, flags) via `httpx`
     (already a dependency),
   - **never raises into the bus** — a failed Slack post must be logged and
     swallowed, like the rest of the persistence path.
3. Be careful with payloads: events are already redacted before persistence
   (`agentmoat/redaction.py`), but double-check you don't widen what's sent.

## Acceptance criteria

- A user can register the sink in a few lines and see critical events arrive.
- Network/HTTP failures are logged, not propagated.
- Unit tests in `tests/` mock the webhook (no real network calls in CI).
- A short README/usage snippet.

## Pointers

- `agentmoat/bus.py` (subscribers), `agentmoat/events.py` (event model)
- `agentmoat/redaction.py` (don't leak secrets into Slack)
- Roadmap item: "Slack/PagerDuty alerting"

## Out of scope

PagerDuty (separate issue), retry/backoff queues, and changing event schemas.
