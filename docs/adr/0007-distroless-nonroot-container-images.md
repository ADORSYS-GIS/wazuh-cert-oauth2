# ADR-0007: Distroless nonroot container images

> Build the server and webhook images from distroless nonroot base images.

## Metadata

| Field | Value |
| :--- | :--- |
| **Document ID** | ADR-0007 |
| **Status** | `Accepted` |
| **Date** | N/A |
| **Deciders** | Wazuh maintainers |
| **Governs** | Dockerfile, Helm charts (runAsUser/runAsGroup) |
| **Amends** | N/A |
| **Amended by** | N/A |
| **Supersedes** | N/A |
| **Superseded by** | N/A |

## Context

The server and webhook handle certificate material and credentials; we wanted to minimize the attack surface of the runtime images.

## Decision

Build the server and webhook images from `gcr.io/distroless/static-debian12:nonroot`, run as `USER nonroot:nonroot`, and set `runAsUser: 1001` / `runAsGroup: 1001` in the Helm charts.

## Consequences

- No shell or package manager in the runtime image, reducing exploit surface.
- No interactive debugging inside the container (logs and sidecar inspection instead).
- Consistent with the [Deployment](https://adorsys.atlassian.net/wiki/x/GoA2t) posture.

## Rollback

Nothing to roll back.
