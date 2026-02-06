# TypeScript Security

- **No `eval()`/`new Function()`**: Never execute user-controlled strings as code.
- **No `child_process` with shell**: Use `execFile`/`spawn` with args array, never `exec(userInput)`.
- **No `any` for untrusted input**: Type external data with `zod`, `io-ts`, or `ajv` schemas.
- **Prototype pollution**: Use `Object.create(null)` for lookup maps. Reject `__proto__`, `constructor`, `prototype` keys from user input.
- **Path traversal**: Use `path.resolve()` + verify result starts with allowed base directory.
- **Secrets**: Never import secrets at module scope. Use `process.env` with runtime checks.
- **Regex DoS**: Avoid unbounded quantifiers on user input. Use `re2` for untrusted patterns.
