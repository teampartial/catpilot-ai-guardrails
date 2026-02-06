# TypeScript Security — Full Reference

> **Framework:** TypeScript (Node.js / Bun / Deno)

---

## Dynamic Code Execution

### ❌ NEVER Do This

```typescript
// DANGEROUS: Arbitrary code execution
eval(userInput)
new Function(userInput)()
setTimeout(userInput, 100)  // String form executes as code
vm.runInNewContext(userInput)
```

### ✅ Always Do This

```typescript
// SAFE: Parse data, don't execute it
const data = JSON.parse(userInput)

// SAFE: If sandboxing is needed, use isolated-vm or similar
import ivm from 'isolated-vm'
const isolate = new ivm.Isolate({ memoryLimit: 128 })
```

---

## Command Execution

### ❌ NEVER Do This

```typescript
import { exec } from 'child_process'

// DANGEROUS: Shell injection
exec(`ls ${userInput}`)
exec(`grep ${pattern} file.txt`)
execSync(`convert ${filename} output.png`)
```

### ✅ Always Do This

```typescript
import { execFile, spawn } from 'child_process'

// SAFE: Array args, no shell interpretation
execFile('ls', ['-la', directory])
spawn('grep', [pattern, 'file.txt'])

// SAFE: If shell is absolutely needed
import { quote } from 'shell-quote'
exec(`grep ${quote([pattern])} file.txt`)
```

---

## Input Validation & Type Safety

### ❌ NEVER Do This

```typescript
// DANGEROUS: Trust user input types
const userId = req.query.id as string
const config = req.body as AppConfig

// DANGEROUS: any on untrusted data
function processData(data: any) { ... }
```

### ✅ Always Do This

```typescript
import { z } from 'zod'

// SAFE: Validate at boundaries
const UserIdSchema = z.string().uuid()
const userId = UserIdSchema.parse(req.query.id)

const ConfigSchema = z.object({
  name: z.string().max(100),
  port: z.number().int().min(1).max(65535),
})
const config = ConfigSchema.parse(req.body)
```

---

## Prototype Pollution

### ❌ NEVER Do This

```typescript
// DANGEROUS: Merging user input into objects
Object.assign(target, userInput)
_.merge(config, userInput)

// DANGEROUS: Direct property access from user input
obj[userKey] = userValue
```

### ✅ Always Do This

```typescript
// SAFE: Use Map for dynamic keys
const lookup = new Map<string, unknown>()

// SAFE: Reject dangerous keys
const DANGEROUS_KEYS = new Set(['__proto__', 'constructor', 'prototype'])
function safeSet(obj: Record<string, unknown>, key: string, value: unknown) {
  if (DANGEROUS_KEYS.has(key)) throw new Error('Invalid key')
  obj[key] = value
}

// SAFE: Use Object.create(null) for lookup objects
const safeObj = Object.create(null) as Record<string, unknown>
```

---

## Path Traversal

### ❌ NEVER Do This

```typescript
import { readFile } from 'fs/promises'

// DANGEROUS: Direct user input as path
const content = await readFile(req.query.path as string)
const file = await readFile(`uploads/${req.params.filename}`)
```

### ✅ Always Do This

```typescript
import { resolve, basename } from 'path'
import { readFile } from 'fs/promises'

const ALLOWED_DIR = resolve('/app/uploads')

// SAFE: Resolve and validate
const safeName = basename(userInput)  // Strip directory components
const safePath = resolve(ALLOWED_DIR, safeName)

if (!safePath.startsWith(ALLOWED_DIR)) {
  throw new Error('Path traversal detected')
}

const content = await readFile(safePath)
```

---

## Secrets Management

### ❌ NEVER Do This

```typescript
// DANGEROUS: Hardcoded secrets
const API_KEY = "sk-live-abc123"
const DB_URL = "postgres://admin:password@prod.db.com/main"

// DANGEROUS: Secrets in module scope (imported before env is loaded)
export const config = {
  apiKey: process.env.API_KEY!,  // May be undefined at import time
}
```

### ✅ Always Do This

```typescript
// SAFE: Runtime access with validation
function getRequiredEnv(key: string): string {
  const value = process.env[key]
  if (!value) throw new Error(`Missing required env var: ${key}`)
  return value
}

// SAFE: Lazy initialization
let _apiKey: string | undefined
export function getApiKey(): string {
  _apiKey ??= getRequiredEnv('API_KEY')
  return _apiKey
}
```

---

## Regex Denial of Service (ReDoS)

### ❌ NEVER Do This

```typescript
// DANGEROUS: Catastrophic backtracking on user input
const emailRegex = /^([a-zA-Z0-9_\.\-])+\@(([a-zA-Z0-9\-])+\.)+([a-zA-Z]{2,4})+$/
userInput.match(emailRegex)

// DANGEROUS: User-controlled regex
new RegExp(userInput).test(content)
```

### ✅ Always Do This

```typescript
// SAFE: Use re2 for untrusted patterns
import RE2 from 're2'
const pattern = new RE2(userInput)

// SAFE: Use well-tested validation libraries
import { z } from 'zod'
const email = z.string().email().parse(userInput)
```

---

*Full guardrails: [FULL_GUARDRAILS.md](../../FULL_GUARDRAILS.md)*
