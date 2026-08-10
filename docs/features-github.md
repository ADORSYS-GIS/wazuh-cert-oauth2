---
layout: default
title: GitHub issue tracking
parent: Features
nav_order: 6
---

# GitHub issue tracking

When a new user registers or is created in the identity provider, the Webhook Proxy automatically opens a **tracking issue** in a configured GitHub repository, giving operators a visible record of every new enrollment to review or act on.

## How it works

1. The IdP (e.g. Keycloak) fires a user-registration / user-created event to `POST /api/webhook`.
2. The webhook extracts the user metadata from the payload.
3. It creates an issue via the GitHub API: `POST /repos/{owner}/{repo}/issues`.

## Configuration

| Flag | Env Variable | Purpose |
| :--- | :--- | :--- |
| `--github-token` | `GITHUB_TOKEN` | GitHub Personal Access Token for issue creation. |
| `--github-repo-owner` | `GITHUB_REPO_OWNER` | Owner of the repository for tickets. |
| `--github-repo-name` | `GITHUB_REPO_NAME` | Name of the repository for tickets. |

> Prefer a **fine-grained** PAT scoped to **Issue Creation** on the target repository.

## Resiliency

If the GitHub API is unreachable or returns a 5xx, the ticket request is **spooled** and retried in the background (see [Reliability & spooling](../features-reliability)), so enrollment records aren't lost to transient API failures.
