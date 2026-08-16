# Node.js adversary

Reviews Node.js for security hazards and lifecycle cleanup leaks.

## Goals

The adversary is designed to produce a small number of high-confidence,
actionable findings grounded in concrete repository evidence. Its review should
be deterministic where possible, explicit about impact, and quiet when the
available evidence does not justify a finding.

## Scope

It evaluates Node.js source for command execution, dynamic evaluation, TLS, path confinement, weak randomness, VM isolation, and shared listener cleanup.

The complete detector or review inventory is maintained in
[CHECKS.md](CHECKS.md).

## Boundaries

It owns framework- or language-specific review in this domain. Infrastructure, CI, dependency-manager, and unrelated application concerns remain with specialist adversaries.
