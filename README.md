# SentinelGuard AI

Suspicious phishing and scam messages, as well as malicious web/API input, can be difficult to understand from a simple warning. **SentinelGuard inspects submitted text and structured JSON payloads**, uses deterministic rules to detect supported security indicators, shows the matched evidence, assesses heuristic risk, and provides defensive recommendations.

> **Don't just tell me there's a threat. Show me why.**

Deterministic rules are authoritative for patterns they recognize. This bounded heuristic engine is not complete vulnerability or malware detection; a clean result is not proof that input is safe. Phishing indicators are not external URL, sender, or domain reputation checks. Featherless AI enrichment is optional, supplementary, and only requested for an inspection when the user explicitly consents.

## Features

- Text inspection and structured JSON payload inspection.
- Deterministic indicators for SQL injection, XSS, command injection, path traversal, and phishing.
- Stable rule IDs, bounded/redacted evidence, per-finding recommendations, classification, severity, and score from 0 to 100.
- Optional Featherless AI enrichment through a provider-neutral boundary, with result validation and deterministic fallback.
- Browser demo with safe static examples, responsive inspection/results view, local history, history-based summary metrics, JSON report download, and print.
- Browser history is bounded and remains in local storage on the current device. The server does not persist inspections.

## Requirements

- Node.js 20.13 or newer.
- npm.

## Setup and run

```sh
npm install
npm start
```

Open `http://localhost:3000`. During development, `npm run dev` uses Node's built-in watch mode.

Copy `.env.example` to `.env` and add a local `FEATHERLESS_API_KEY` only if you want optional AI enrichment. Set `FEATHERLESS_MODEL=Qwen/Qwen2.5-7B-Instruct` to use the documented, currently listed Qwen model. Do not commit `.env`, and never paste a real secret into chat, logs, source files, screenshots, or GitHub.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `NODE_ENV` | `development` | Runtime mode: `development`, `test`, or `production`. |
| `PORT` | `3000` | HTTP listener port. |
| `CORS_ORIGINS` | `http://localhost:3000` in development | Comma-separated exact HTTP(S) origins; production requires explicit origins. |
| `JSON_BODY_LIMIT` | `32kb` | Express JSON body limit, maximum 1mb. |
| `MAX_INPUT_CHARS` | `32000` | Maximum text inspection size. |
| `RATE_LIMIT_WINDOW_MS` | `60000` | Request-rate window in milliseconds. |
| `RATE_LIMIT_MAX` | `60` | Requests allowed per window per client IP. |
| `LOG_LEVEL` | `info` | Minimum JSON log level. |
| `FEATHERLESS_API_KEY` | unset | Optional bearer token for supplemental AI enrichment. When absent, the AI boundary remains unavailable and deterministic inspection is authoritative. |
| `FEATHERLESS_MODEL` | `Qwen/Qwen2.5-7B-Instruct` | Model identifier used for Featherless requests. |

Health requests are excluded from the in-memory inspection rate limiter. The limiter is intended for a single-process demo, not coordinated across instances.

## Architecture

- `public/` contains the static, same-origin browser demo. It uses the existing backend APIs; it does not implement duplicate detection logic.
- `src/src/routes/` handles health and versioned inspection requests.
- `src/src/middleware/` contains security, request validation, IDs, and centralized safe errors.
- `src/src/detection/` implements deterministic rule matching, explainable findings, and score calculation.
- `src/src/services/inspectionService.js` runs deterministic analysis first and calls the AI boundary only when that inspection carries explicit consent and is not identified as containing common secrets.
- `src/src/ai/analyzer.js` validates optional supplementary AI data and fails safely.
- `src/src/ai/privacy.js` redacts common secret patterns, bounds provider context, and detects inputs that should not be sent externally.
- `src/src/ai/featherless.js` implements the server-side Featherless OpenAI-compatible adapter. On consented and eligible inspections, it sends a redacted excerpt of at most 1,200 characters plus minimal deterministic metadata to the fixed endpoint `https://api.featherless.ai/v1/chat/completions`.

## Demo

The demo illustrates phishing, SQL injection, command injection with multiple indicators, and clean input. Each inspection shows matched evidence, heuristic risk, and defensive recommendations. The examples are only submitted to SentinelGuard for analysis; they do not execute code or visit links.

Choose **Text inspection** or **JSON payload**, enter content or select a static example, and click **Inspect input**. Available examples include SQL injection, XSS, path traversal, command injection, phishing indicators, benign security discussion, and a structured JSON payload.

The results view displays risk, classification, severity, rule IDs, explanations, bounded evidence, and recommended actions. AI status distinguishes analysis not requested, skipped due to detected secrets, and unavailable. Inspection history and dashboard metrics derive only from results stored locally in this browser. History stores a short input preview (with common password, token, API-key, and authorization-shaped values redacted) and bounded result data, not the full inspected input. JSON exports also redact these common credential-shaped values. This is heuristic redaction, not reliable secret discovery; review exported reports before sharing them. Use **Clear history** to remove local history.

The JSON export includes a bounded input representation (up to 2,000 characters), results, and timestamps. When exporting a saved history entry, the input is identified as a preview rather than the original full input. Use the print control for a printable report.

## API

### `GET /health`

Returns the lightweight existing service health response; it does not depend on AI or external services.

### `POST /api/v1/inspect`

Request:

```json
{
  "user_input": "' OR '1'='1",
  "ai_consent": false
}
```

`ai_consent` is optional and defaults to `false`; only set it to `true` when the caller explicitly agrees to the disclosed external processing. The same field is supported by the payload inspection endpoint.

### `POST /api/v1/inspect/payload`

Request:

```json
{
  "payload": {
    "username": "admin",
    "query": "' OR '1'='1",
    "comment": "<script>alert(1)</script>"
  }
}
```

Responses include `success`, `riskScore`, `classification`, `severity`, `findings`, `recommendations`, and `ai`. Findings contain a stable `ruleId`, category, severity, description, bounded evidence, and recommendation. Structured payload inspection only accepts JSON objects or arrays and bounds depth, item count, and normalized content size.

Validation failures return 400, unsupported request content types return 415, oversized requests return 413, rate limits return 429, and unknown routes return 404. Error responses do not include stack traces. Requests include an `X-Request-Id` response header; supplied IDs are accepted only in UUID form.

## Deterministic detection and scoring

The rules include representative SQL tautology, UNION, and comment patterns; script/event-handler/JavaScript-URL XSS; selected shell substitutions and command/operator combinations; traversal and encoded traversal; and selected phishing urgency, credential, payment, and URL-obfuscation indicators. This is not comprehensive coverage.

Each finding contributes to a bounded multiplicative score:

`score = round(100 * (1 - product(1 - contribution / 100)))`

Contributions are informational 5, low 15, medium 30, high 50, and critical 70. The resulting score is clamped to 0–100. Scores below 30 are low, 30–69 medium, and 70–100 high/critical. A score of 90 or above maps to critical overall severity; findings may independently have higher severity than the score band. With no finding, the score is 0 and classification is `clean`. Scores represent SentinelGuard's internal assessment, not probability.

## AI enrichment and security model

Every inspection runs deterministic analysis locally on the SentinelGuard server. Featherless processing is opt-in per inspection: the browser consent checkbox starts unchecked, is sent as `ai_consent`, and is reset after each inspection. API callers must send `"ai_consent": true` to request optional enrichment; existing requests that omit the field continue to receive deterministic analysis only. Consent allows up to 1,200 characters of redacted inspection content and minimal deterministic metadata to be sent to Featherless at `https://api.featherless.ai/v1/chat/completions`. Common credential patterns are redacted; if the input matches patterns for passwords, tokens, authorization credentials, private keys, or selected provider tokens, external analysis is skipped entirely. These checks are heuristic and cannot guarantee secret discovery or removal, so do not submit highly sensitive material even with consent.

When the provider is unconfigured, not requested, skipped as sensitive, times out, rate-limits, returns malformed data, or is otherwise unavailable, deterministic results remain authoritative and AI enrichment is omitted or marked unavailable. AI output is strictly schema-validated and cannot change deterministic score, classification, severity, or findings. Never treat AI output or inspected content as executable instructions. Featherless privacy, retention, and processing practices are governed by its current terms and should be reviewed before sending sensitive or regulated data.

Helmet, exact-origin CORS, rate limiting, JSON and payload limits, server-side validation, request IDs, and sanitized structured request logging are enabled. Browser output is rendered as text, not interpreted HTML. Browser history has fixed count and serialized-size limits.

## Testing

```sh
npm test
npm audit
```

Tests cover API routes, health regression, consent validation, deterministic threat indicators and benign examples, risk scoring, secret screening/redaction, and mocked AI success, errors, malformed responses, timeout, and fallback behavior.

## Limitations and roadmap

- Pattern matching can produce false positives and false negatives and is not a substitute for contextual application security testing.
- No external threat intelligence is connected. A real Featherless inference request has not been verified by the automated tests.
- Local history is browser-specific and can be cleared by the user or browser storage policies.
- No accounts, authentication, database, webhooks, deployment manifests, or persistent server-side event history are included.
- Featherless enrichment sends data externally only after explicit per-inspection consent.
