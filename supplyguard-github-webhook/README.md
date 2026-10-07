# SupplyGuard GitHub Webhook Trigger V1

This is the GitHub-trigger entry point for SupplyGuard. It removes the manual package/version UI from the primary workflow.

## Flow

```text
Developer / Dependabot PR
        |
        | pull_request: opened / synchronize / reopened
        v
GitHub Webhook
        |
        v
POST /api/github/webhook
        |
        +--> verify X-Hub-Signature-256
        |
        +--> fetch PR changed files
        |
        +--> read package.json at base/head SHA
        |
        +--> read package-lock.json when changed
        |
        +--> detect direct dependency version changes
        |
        v
analysis queue: data/github_dependency_update_queue.jsonl
```

The current bridge queues exact old/new package versions. It deliberately does not execute package code or lifecycle scripts.

## Requirements

- Java 22
- Maven 3.6.3+
- A GitHub repository where you have admin access
- A GitHub token with read access to pull requests and repository contents when analyzing private repositories
- A webhook secret
- A publicly reachable HTTPS URL for GitHub to call (for local testing, use a tunnel such as ngrok)

Spring Boot 3.5.16 supports Java 17 through 25, so Java 22 is supported. See the official requirements: https://docs.spring.io/spring-boot/3.5/system-requirements.html

## Environment variables

Windows CMD:

```cmd
set GITHUB_TOKEN=YOUR_GITHUB_TOKEN
set GITHUB_WEBHOOK_SECRET=YOUR_RANDOM_WEBHOOK_SECRET
```

Do not hard-code either value in source code or commit them to GitHub.

## Start

```cmd
mvn spring-boot:run
```

Health check:

```text
http://localhost:8080/api/github/health
```

## Configure the GitHub repository webhook

In GitHub: Repository -> Settings -> Webhooks -> Add webhook.

Payload URL:

```text
https://YOUR_PUBLIC_HOST/api/github/webhook
```

Content type: `application/json`

Secret: use the same `GITHUB_WEBHOOK_SECRET` value.

Choose only the `Pull requests` event and keep the webhook active.

SupplyGuard reacts to these pull-request actions:

- opened
- synchronize
- reopened

When the webhook is created, GitHub sends a ping event; SupplyGuard accepts the signed ping without starting analysis.

## What happens on a dependency PR

Example:

```json
"dependencies": {
  "express": "4.18.2"
}
```

becomes:

```json
"dependencies": {
  "express": "4.21.0"
}
```

SupplyGuard queues:

```text
repository = owner/repo
pullRequest = 42
package = express
oldVersion = 4.18.2
newVersion = 4.21.0
baseSha = ...
headSha = ...
```

For semver ranges, `package-lock.json` is used when available to recover exact resolved versions.

## Scope of this V1 trigger point

Supported now:

- GitHub repository webhook
- Pull-request triggers
- Signature verification
- Duplicate delivery suppression (in-memory)
- Changed-file inspection
- package.json dependency-delta detection
- package-lock.json exact-version resolution
- JSONL analysis queue

Not yet connected here:

- calling the existing Python artifact/static-analysis pipeline directly
- publishing the final risk report back to GitHub
- persistent database storage for webhook deliveries/jobs

Those are the next integration steps after this trigger point is validated.

## Security notes

GitHub recommends validating the `X-Hub-Signature-256` HMAC header when a webhook secret is configured. This implementation verifies the signature against the original request bytes before parsing the payload.

SupplyGuard reads repository files at GitHub commit SHAs and does not install, run, or execute packages.
