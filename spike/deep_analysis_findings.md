# Deep Analysis Findings — Hypothesis Generation

## Emergent Patterns from Spike Data (n=16)

### Finding 1: The Secrets-Gateway Effect
Servers with secrets access average 5.3 categories vs. 1.2 for those without — a 4.4x multiplier. Secrets access (process.env / os.getenv) appears to be a "gateway" capability: once a server reads environment variables, it almost always also touches the filesystem, network, and more.

### Finding 2: The TypeScript Sprawl
TypeScript servers average 5.1 categories and ASS=38.3 vs. Python servers at 2.6 categories and ASS=18.7. The TypeScript ecosystem (npm) appears to produce more capability-rich servers than PyPI.

### Finding 3: Ingress as Risk Multiplier
Servers with network ingress (listening on a port) average ASS=42.9 vs. 12.7 without — a 30.2-point gap. Ingress is the strongest single predictor of high attack-surface scores.

### Finding 4: The filesystem+secrets+ingress Triad
The triple (filesystem, ingress, secrets) co-occurs in 50% of all servers. This is the most common dangerous combination — a server that reads files, listens on a port, and accesses credentials.

### Finding 5: Shell Always Co-occurs
When shell is detected, filesystem is ALWAYS also detected (100%). Shell never appears in isolation. This suggests shell-capable servers are inherently "kitchen sink" implementations.

### Finding 6: Impersonation is the Rarest but Most Dangerous Cluster
Only 2/16 servers have impersonation, but both have ALL other categories too (100% co-occurrence with everything). Servers that send emails/messages on behalf of users are universally high-risk.

### Finding 7: Category Count Strongly Predicts Score
Pearson r = 0.935 between number of detected categories and the final ASS. The score function is dominated by breadth, not depth. This needs investigation — is breadth the right dominant signal?

### Finding 8: Depth Dominates High Scores, Exposure Dominates Mid-Range
For the top 2 servers (ASS > 50), Depth is the dominant component. For mid-range servers (ASS 40-51), Exposure dominates. This suggests two distinct risk profiles.
