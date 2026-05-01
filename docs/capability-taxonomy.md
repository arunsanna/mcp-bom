# MCP Capability / Permission Taxonomy

> Locked v1 eight-category permission scope taxonomy for the MCP-BOM static extractor. Each category is detected via API/source patterns plus declared schema parsing of `tools/list` entries.

## v1 Scope Decisions

MCP-BOM keeps exactly eight top-level categories for v1. Edge cases are folded into the closest capability category so the extractor output stays stable across the corpus run.

- Unsafe deserialization is classified under **Shell / Process Execution** when it can lead to code execution from untrusted input. It is a code-execution vector even when no shell binary is invoked.
- Generic outbound HTTP is **Network Egress** only. It becomes **Inter-Server Delegation** only when the code uses an MCP client, JSON-RPC MCP methods, a known MCP transport path such as `/sse` or `/mcp`, or explicit tool-calling semantics.
- Database access does not create a ninth category. Remote database clients are **Network Egress** with datastore protocol metadata; local database files are **Filesystem**; sensitive records surfaced through tools are captured by **Data Egress Sensitivity**.

## The Eight Categories

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
- Unsafe deserialization/code-evaluation: Python `pickle.load(s)`, `dill.load(s)`, `marshal.load(s)`, `yaml.load` without `SafeLoader`; Node `vm.runIn*`, dynamic `Function`, unsafe template/eval loaders.
- Tool description heuristics: words like "run", "execute", "shell", "command", "script".

Sub-fields:

- direct / sandboxed
- shell-interpreted (true/false)
- arbitrary args (true/false)
- code-evaluation vector: eval / unsafe deserialization / dynamic module load

### 3. Network Egress

What it covers: outbound HTTP, raw socket connections, allowlist vs arbitrary host.

Detection patterns:

- Python: `requests`, `httpx`, `urllib`, `aiohttp`, `socket.connect`.
- Node/TS: `fetch`, `axios`, `node-fetch`, `http.request`, `https.request`.
- Go: `net/http`, `net.Dial`.
- Remote datastores: PostgreSQL/MySQL/Redis/MongoDB/Elasticsearch clients when the connection target is remote.

Sub-fields:

- arbitrary host / allowlisted host
- protocol set (HTTP/S, raw TCP, UDP, datastore)

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
- HTTP calls to known MCP transport URIs in code: `/sse`, `/mcp`, JSON-RPC `tools/list`, `tools/call`, `resources/list`, or explicit MCP session initialization.

Sub-fields:

- static (declared at startup) / dynamic (resolved at runtime)
- count: number of other MCP servers reachable
- evidence: MCP SDK / transport path / JSON-RPC MCP method / declared remote server

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
- Database access surfaces: SQL query builders/ORMs and database clients when tool outputs expose user, customer, patient, financial, location, message, or credential records.
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

## Frozen Day 1 Decisions

- Unsafe deserialization: **Shell / Process Execution**, flagged as `code_evaluation_vector="unsafe_deserialization"` when reachable from untrusted input.
- Generic HTTP: **Network Egress** unless MCP-specific client/transport/method evidence is present; `/sse` or `/mcp` paths count as delegation only when paired with client-side MCP semantics.
- Database access: no ninth category. Remote DB connectivity contributes to **Network Egress**; local DB files contribute to **Filesystem**; sensitive result exposure contributes to **Data Egress Sensitivity**.
