# Node.js adversary

Reviews Node.js for security hazards and lifecycle cleanup leaks.

## Checks

- **Application executes dynamically constructed JavaScript:** Replace dynamic evaluation with explicit parsing or dispatch.
- **Node.js constructs a shell command from input:** Use execFile or spawn with a validated argument array.
- **Node.js disables TLS certificate verification:** Keep verification enabled and configure trusted roots.
- **Lifecycle cleanup leaves sibling EventEmitter listeners attached:** Unregister every lifecycle event that shares a cleanup callback.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```

## Automatic detection

`adversary auto` selects the nodejs adversary when changes include `**/*.js` or `**/*.mjs`, plus the other domain-specific patterns declared in `adversary.yaml`. Unrelated changes do not select it.
