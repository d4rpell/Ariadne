# ADR-0021: Lab and integration validation

- Date: 2026-09-27
- Status: Lab scope confirmed by the owner; technical design proposed, subject to host preflight. Not deployed or verified.
- Relationships: Complements ADR-0019 and ADR-0020; supersedes none. Does not ratify either proposal or change collector privileges or evidence contracts.

## Decision

Prepare a reproducible synthetic Kubernetes lab on the existing verification host, with planning separated from subsequent execution. Prefer a single-node kind cluster using rootless Podman, a loopback API endpoint, bounded resources and dedicated artifacts, subject to successful preflight.

## Context

Ariadne is pre-alpha. Documentation and mocks do not demonstrate a working Prisma integration. There is currently no verified Prisma test environment. The available ARM64 verification host is shared; its current runtime and capacity must be checked before deployment.

## Options considered

1. Mocks only: reproducible and inexpensive, but insufficient for real Kubernetes integration checks.
2. Rootless kind: a limited, removable Kubernetes lab, dependent on compatible runtime and cgroup delegation.
3. A host-installed Kubernetes distribution: greater service and network impact on a shared host.
4. A separate host or an OpenShift environment: stronger separation or better target fidelity, requiring additional resources and access.

## Why this option

kind provides real API and RBAC exercises with a smaller operational scope than installing a server distribution on the shared host. Rootless operation reduces host privileges but is not VM isolation. Failed prerequisites must lead to a documented blocker, not an automatic switch to privileged deployment or host-wide changes.

## Consequences and limits

Use synthetic workloads and record versions, commands and results. Distinguish mock tests, Kubernetes lab tests and actual Prisma integration tests. A lab RBAC fixture does not establish the future collector's permission contract. Lab availability does not prove cross-architecture determinism or OpenShift compatibility.

Keep private planning and external credentials off the shared host. Protect lab-generated access configuration. Do not alter unrelated services or global host settings as an incidental repair. Persistent test storage demonstrates survival across tested pod replacement, not production durability or disaster recovery.

A vendor trial may provide a route to Prisma validation, but individual eligibility and Compute API access remain unconfirmed. An illustrative repository animation must identify synthetic or planned stages and must not imply a verified end-to-end integration.

## Revisit conditions

Revisit if rootless prerequisites or resource limits cannot be met, interference is observed, a vendor component or external credentials are needed, or OpenShift validation becomes necessary. Independent review and execution evidence remain pending.

## References

- [kind quick start](https://kind.sigs.k8s.io/docs/user/quick-start/)
- [kind rootless requirements](https://kind.sigs.k8s.io/docs/user/rootless/)
- [Prisma Cloud trial request](https://start.paloaltonetworks.com/prisma-cloud-request-a-trial)
