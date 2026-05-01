# MCP Capability / Permission Taxonomy

> Eight-category permission scope taxonomy for the MCP-BOM static extractor. Each category is detected via API/source patterns plus declared schema parsing of `tools/list` entries.

## The Nine Categories

### 1. Filesystem

What it covers: read, write, delete, traversal scope of local files. Includes both explicit file APIs and indirect access (e.g., file URIs in tool inputs).

Detection patterns:

- Python: `open()`, `pathlib.Path`, `os.path`, `shutil`, `os.remove`, `os.unlink`, `tempfile`, `aiofiles`.
- Node/TS: `fs`, `fs/promises`, `fs.createReadStream`, `fs.createWriteStream`, `node:fs`.
- Go: `os.Open`, `os.WriteFile`, `ioutil`.
- Schema heuristics: `path`, `filename`, `directory`, `file_url` properties in tool inputSchema.

Sub-fields:

- read / write / delete
- scope: cwd-only / user-home / system-wide / arbitrary

### 2. Shell / Process Execution

What it covers: direct command execution, sandboxed exec, subprocess invocation, shell-out via libraries, container escape vectors.

Detection patterns:

- Python: `subprocess.run`, `subprocess.Popen`, `os.system`, `os.exec*`, `pty.spawn`, `eval`, `exec`.
- Node/TS: `child_process.exec`, `child_process.spawn`, `execSync`, `shelljs`.
- Go: `os/exec.Command`, `syscall.Exec`.
- Tool description heuristics: words like "run", "execute", "shell", "command", "script".

Sub-fields:

- direct / sandboxed
- shell-interpreted (true/false)
- arbitrary args (true/false)

### 3. Network Egress

What it covers: outbound HTTP, raw socket connections, allowlist vs arbitrary host.

Detection patterns:

- Python: `requests`, `httpx`, `urllib`, `aiohttp`, `socket.connect`.
- Node/TS: `fetch`, `axios`, `node-fetch`, `http.request`, `https.request`.
- Go: `net/http`, `net.Dial`.

Sub-fields:

- arbitrary host / allowlisted host
- protocol set (HTTP/S, raw TCP, UDP)

### 4. Network Ingress

What it covers: server bind interface, auth required, TLS posture.

Detection patterns:

- Express/Fastify/Flask listen calls; check bind address (`0.0.0.0` vs `127.0.0.1`).
- TLS configuration (cert path, https vs http listener).
- Auth middleware presence (Bearer, OAuth2, mTLS, none).

Sub-fields:

- bind: localhost / 0.0.0.0 / specific
- auth: none / api-key / oauth / mTLS
- TLS enabled (true/false)

### 5. Secrets and Credentials

What it covers: env var read, keychain access, OAuth token handling, secret manager calls.

Detection patterns:

- Python: `os.environ`, `os.getenv`, `keyring`.
- Node/TS: `process.env`, `dotenv`.
- Go: `os.Getenv`.
- Library imports: `boto3` (AWS Secrets Manager), `azure-keyvault-secrets`, `google-cloud-secret-manager`.

Sub-fields:

- read / write / list
- scope: process env / system keychain / cloud KMS

### 6. Inter-Server Delegation

What it covers: calls to other MCP servers, tool-of-tools chaining, A2A protocol invocations.

Detection patterns:

- MCP client SDK imports: `@modelcontextprotocol/sdk` client classes, `mcp.ClientSession` (Python).
- A2A SDK imports.
- HTTP calls to known MCP transport URIs in code.

Sub-fields:

- static (declared at startup) / dynamic (resolved at runtime)
- count: number of other MCP servers reachable

### 7. Human Impersonation

What it covers: email, messaging, calendar, social media posting on behalf of a user.

Detection patterns:

- Library imports: `smtplib`, `imaplib`, `googleapiclient` (Gmail/Calendar), `slack_sdk`, `tweepy`, `discord.py`.
- Tool description heuristics: words like "send", "post", "message", "publish", "tweet", "email".

Sub-fields:

- channels: email / chat / social / calendar
- approval gate (true/false)

### 8. Data Egress Sensitivity

What it covers: PII handling, log content sensitivity, attachment upload.

Detection patterns:

- Imports: `cryptography.fernet`, `hashlib` (hashing PII), libraries that handle PHI/PII.
- Tool descriptions mentioning user data fields.
- Output schema fields for messages, emails, addresses.

Sub-fields:

- categories: PII, PHI, financial, location, none-detected
- redaction declared (true/false)

## Capability Scope Vector

Per server, output is an 8-tuple of records:

```json
{
  "filesystem": {
    "detected": true,
    "read": true,
    "write": true,
    "delete": false,
    "scope": "user-home"
  },
  "shell": {
    "detected": true,
    "direct": true,
    "sandboxed": false,
    "shell_interpreted": true,
    "arbitrary_args": true
  },
  "egress": {
    "detected": true,
    "arbitrary_host": true,
    "protocols": ["http", "https"]
  },
  "ingress": { "detected": false },
  "secrets": { "detected": true, "read": true, "scope": "process-env" },
  "delegation": { "detected": false },
  "impersonation": { "detected": false },
  "data_sensitivity": { "detected": false }
}
```

## Confidence Levels

Each detected category carries a confidence:

- `high` — direct API call detected (e.g., `subprocess.run`)
- `medium` — library imported but specific usage not confirmed
- `low` — schema heuristic match only (e.g., a `path` parameter could be filesystem or just a string)

Confidence affects score weighting in the score function.

### 9. Database / Persistence

What it covers: direct connection to SQL/NoSQL databases, ORM usage, key-value stores. This is distinct from generic network egress because it specifically indicates the server can exfiltrate, modify, or drop structured data stores.

Detection patterns:

- Python: `sqlite3`, `psycopg2`, `SQLAlchemy`, `pymongo`, `redis`, `motor`.
- Node/TS: `pg`, `mysql2`, `mongoose`, `prisma`, `typeorm`.
- Go: `database/sql`, `gorm`.

Sub-fields:

- read / write / delete
- type: relational / nosql / key-value

## Open Questions Resolved (May 1)

- **Unsafe Deserialization:** Classified under **Shell / Process Execution**. Functions like `yaml.unsafe_load` or `pickle.load` in Python inherently carry arbitrary code execution risk, which aligns with the threat model of shell execution rather than mere filesystem access.
- **Inter-server delegation:** An HTTP call to a generic URL counts as **Inter-Server Delegation** ONLY if the path explicitly targets known MCP transport URIs (e.g., `/sse`, `/mcp`). Generic HTTP calls fall under **Network Egress**.
- **Database access:** Added as the 9th category (Database / Persistence) above. Folding it into network egress dilutes the specific risk of data exfiltration or SQL injection inherent to database connections.
