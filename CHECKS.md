# Checks

| Rule | Severity | Scans for |
| --- | --- | --- |
| `nodejs.dynamic-eval` | High | Dynamic code evaluation on non-literal input |
| `nodejs.event-listener-cleanup` | Medium | A shared lifecycle cleanup callback leaves sibling EventEmitter listeners attached |
| `nodejs.path-traversal` | High | Filesystem access from user-influenced paths without confinement |
| `nodejs.shell-exec` | Critical | Shell execution with constructed command strings |
| `nodejs.tls-disabled` | High | TLS certificate verification disabled |
| `nodejs.vm-as-sandbox` | Medium | `vm` module used to isolate untrusted code |
| `nodejs.weak-random-token` | Medium | `Math.random()` feeding security identifiers |
