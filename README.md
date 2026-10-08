# SentinelGuard AI

Suspicious phishing and scam messages, as well as malicious web/API input, can be difficult to understand from a simple warning. **SentinelGuard inspects submitted text and structured JSON payloads**, uses deterministic rules to detect supported security indicators, shows the matched evidence, assesses heuristic risk, and provides defensive recommendations.

> **Don't just tell me there's a threat. Show me why.**

Deterministic rules are authoritative for patterns they recognize. This bounded heuristic engine is not complete vulnerability or malware detection; a clean result is not proof that input is safe. Phishing indicators are not external URL, sender, or domain reputation checks. No AI provider is configured in this repository/runtime, and the application currently makes no external AI calls. The provider-neutral AI boundary is optional architecture for possible future enrichment only.

## Features

- Text inspection and structured JSON payload inspection.
- Deterministic indicators for SQL injection, XSS, command injection, path traversal, and phishing.
- Stable rule IDs, bounded/redacted evidence, per-finding recommendations, classification, severity, and score from 0 to 100.
- Provider-neutral AI result contract with schema validation and deterministic fallback, reserved for optional future enrichment. No provider SDK, provider credentials, or external AI calls are configured.
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

Copy `.env.example` to `.env` to customize local settings. Do not commit `.env`. No secret is required for the current application.

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

Health requests are excluded from the in-memory inspection rate limiter. The limiter is intended for a single-process demo, not coordinated across instances.

## Architecture

- `public/` contains the static, same-origin browser demo. It uses the existing backend APIs; it does not implement duplicate detection logic.
- `src/src/routes/` handles health and versioned inspection requests.
- `src/src/middleware/` contains security, request validation, IDs, and centralized safe errors.
- `src/src/detection/` implements deterministic rule matching, explainable findings, and score calculation.
- `src/src/services/inspectionService.js` runs deterministic analysis first and then calls the provider-neutral AI boundary.
- `src/src/ai/analyzer.js` validates optional supplementary AI data and fails safely. No provider adapter or external model is configured.

## Demo

The demo illustrates phishing, SQL injection, command injection with multiple indicators, and clean input. Each inspection shows matched evidence, heuristic risk, and defensive recommendations. The examples are only submitted to SentinelGuard for analysis; they do not execute code or visit links.

Choose **Text inspection** or **JSON payload**, enter content or select a static example, and click **Inspect input**. Available examples include SQL injection, XSS, path traversal, command injection, phishing indicators, benign security discussion, and a structured JSON payload.

The results view displays risk, classification, severity, rule IDs, explanations, bounded evidence, and recommended actions. AI status is explicitly marked unavailable when no provider is configured. Inspection history and dashboard metrics derive only from results stored locally in this browser. History stores a short input preview (with common password, token, API-key, and authorization-shaped values redacted) and bounded result data, not the full inspected input. JSON exports also redact these common credential-shaped values. This is heuristic redaction, not reliable secret discovery; review exported reports before sharing them. Use **Clear history** to remove local history.

The JSON export includes a bounded input representation (up to 2,000 characters), results, and timestamps. When exporting a saved history entry, the input is identified as a preview rather than the original full input. Use the print control for a printable report.

## API

### `GET /health`

Returns the lightweight existing service health response; it does not depend on AI or external services.

### `POST /api/v1/inspect`

Request:

```json
{
  "user_input": "' OR '1'='1"
}
```

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

The application currently has **no AI provider configured**. It does not make AI/network calls. The provider-neutral boundary marks inspected input as untrusted, strictly validates supplementary output, and returns deterministic results if an adapter is absent, times out, or fails validation. AI data cannot change deterministic score, classification, or findings. Never treat AI output or inspected content as executable instructions.

Helmet, exact-origin CORS, rate limiting, JSON and payload limits, server-side validation, request IDs, and sanitized structured request logging are enabled. Browser output is rendered as text, not interpreted HTML. Browser history has fixed count and serialized-size limits.

## Testing

```sh
npm test
npm audit
```

Tests cover API routes, health regression, validation, deterministic threat indicators and benign examples, risk scoring, and AI boundary/fallback behavior.

## Limitations and roadmap

- Pattern matching can produce false positives and false negatives and is not a substitute for contextual application security testing.
- No external threat intelligence or real AI provider is connected.
- Local history is browser-specific and can be cleared by the user or browser storage policies.
- No accounts, authentication, database, webhooks, deployment manifests, or persistent server-side event history are included.
- A later phase may add a configured AI provider, event/webhook integration, or further product workflows after explicit integration and secret-management review.
