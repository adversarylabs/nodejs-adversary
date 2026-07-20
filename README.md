# Node.js adversary

Reviews Node.js for dynamic code execution, shell injection, and disabled TLS verification.

## Checks

- **Application executes dynamically constructed JavaScript:** Replace dynamic evaluation with explicit parsing or dispatch.
- **Node.js constructs a shell command from input:** Use execFile or spawn with a validated argument array.
- **Node.js disables TLS certificate verification:** Keep verification enabled and configure trusted roots.

## Development

```sh
npm ci
npm test
adversary validate .
adversary pack --check .
```
