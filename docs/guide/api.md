# REST API

OpenSCM has a REST API for your own tools: CI pipelines that scan a host
before it goes live, dashboards and SIEMs that pull compliance data, and
provisioning that approves new systems. It is available in Community Edition
and SaaS, at:

```
https://your-openscm-server/api/v1beta1
```

!!! info "Beta"
    `v1beta1` is usable and documented, but may still change in 0.x releases.
    Every change is listed in the CHANGELOG. It becomes `/api/v1`, frozen,
    once integrations have used it.

The full reference is the OpenAPI file, [`openapi.yaml`](../api/openapi.yaml).
Load it into any OpenAPI viewer or client generator.

---

## Quick start

**1. Create a token.** In OpenSCM, open the user menu (top right) →
**API tokens**. Under **Create Token**, give it a name, pick the lowest role
that does the job (Viewer to read, Runner to run policies and save reports,
Editor to change systems and policies, Admin for the audit log and agent
upgrades), and click **Create**. Copy the token: it is shown only once.

**2. Keep it out of your scripts.** Put it in an environment variable, or
your CI system's secret store, and refer to that:

```bash
export OPENSCM_TOKEN='oscm_api_…'
export API=https://your-openscm-server/api/v1beta1
```

**3. Make the first call.** `/me` says who the token acts as:

```bash
curl -s -H "Authorization: Bearer $OPENSCM_TOKEN" "$API/me"
```

```json
{
  "user": {"id": 1, "username": "alice"},
  "organization": "default",
  "role": "viewer",
  "token": {"name": "ci-pipeline", "expires_at": "2027-01-27T19:44:02Z"}
}
```

A `401` means the token is wrong, expired or revoked; a `403` on a later
call means its role is too low for that call.

The [examples](#examples) below use [`jq`](https://jqlang.github.io/jq/) to
read the JSON, and these two variables:

```bash
AUTH="Authorization: Bearer $OPENSCM_TOKEN"
API=https://your-openscm-server/api/v1beta1
```

---

## API tokens

Every request carries an **API token**. Create one from the user menu (top
right) → **API tokens**:

| Field | Meaning |
|---|---|
| **Name** | What the token is for, e.g. `ci-pipeline`. |
| **Role** | What the token may do: Viewer, Runner, Editor or Admin. At most your own role. |
| **Expires** | In 30 days, 90 days (default), a year, or never. |

The token is shown **once**, when it is created. OpenSCM keeps only a hash of
it, so a lost token can't be shown again; revoke it and create another.

A token works in your organization only, and always within your **current**
role: if your role is lowered, your tokens' roles are lowered with it.
Deleting your account, or suspending the organization, stops your tokens at
once. You see and revoke your own tokens; Admins see and can revoke every
token in the organization.

API tokens are only for the API: they can't be used to sign in, and the API
doesn't accept a signed-in browser session.

---

## Making requests

Send the token in the `Authorization` header:

```bash
curl -H "Authorization: Bearer oscm_api_…" \
  https://your-openscm-server/api/v1beta1/me
```

```json
{"user": {"id": 1, "username": "alice"}, "organization": "default",
 "role": "runner", "token": {"name": "ci-pipeline", "expires_at": "2027-01-25T12:31:02Z"}}
```

Bodies are JSON (`Content-Type: application/json`). Timestamps are ISO 8601
UTC with `Z`.

### Lists and paging

Lists return a page and, if there is more, a cursor for the next one:

```json
{"data": [ … ], "next_cursor": "MTAw"}
```

Request the next page with `?cursor=MTAw`. `limit` sets the page size, 1–1000
(default 100).

### Errors

Errors have one shape, with the HTTP status:

```json
{"error": {"code": "forbidden", "message": "This needs the Runner role; this token acts as viewer"}}
```

| Status | `code` | When | What to do |
|---|---|---|---|
| 400 | `invalid_request` | The request or its body is wrong. | Read `message`; it names the problem. |
| 401 | `unauthorized` | No token, or it is unknown, expired or revoked. | Check the header; create a new token if it expired. |
| 403 | `forbidden` | The token's role is too low, or the organization is suspended. | Use a token with the role `message` names. |
| 404 | `not_found` | No such record **in your organization**. | Check the id; another organization's records are never visible. |
| 409 | `conflict` | Not possible in the record's current state. | Read `message`, e.g. no newer agent to upgrade to. |
| 422 | `plan_limit` | SaaS: your plan has no room for another system, policy or report. | Free a slot, or change plan. |
| 429 | `rate_limited` | More than 600 requests a minute with this token. | Wait the `Retry-After` seconds, then retry. |

For example, running a policy with a Viewer token:

```bash
curl -s -X POST -H "$AUTH" "$API/policies/7/run"
```

```json
{"error": {"code": "forbidden", "message": "This needs the runner role; this token acts as viewer"}}
```

With `curl -f`, as in the examples below, an error makes curl exit
non-zero, so a script with `set -e` stops and a CI step fails.

---

## What you can do

Reads need the **Viewer** role unless noted.

| Endpoint | What it does | Role |
|---|---|---|
| `GET /systems` | List systems (`?status=`, `?group=`) | Viewer |
| `GET /systems/{id}` | A system: groups, online state, agent version, compliance, telemetry | Viewer |
| `GET /systems/{id}/compliance` | Every linked policy and each test's latest result, with evidence | Viewer |
| `POST /systems/{id}/approve` | Approve a pending system | Editor |
| `DELETE /systems/{id}` | Delete a system | Editor |
| `PUT /systems/{id}/groups` | Set its manual groups: `{"groups": [1, 2]}` | Editor |
| `POST /systems/{id}/upgrade` | Queue an agent upgrade | Admin |
| `PUT /systems/{id}/results/{test_id}/exclusion` | Exclude a finding: `{"reason": "…"}` | Editor |
| `DELETE /systems/{id}/results/{test_id}/exclusion` | Restore it | Editor |
| `GET /groups`, `GET /groups/{id}` | Groups, with members and linked policies | Viewer |
| `GET /tests`, `GET /tests/{id}` | Tests, with their conditions | Viewer |
| `GET /policies`, `GET /policies/{id}` | Policies, with tests and groups | Viewer |
| `GET /policies/{id}/compliance` | The live policy report | Viewer |
| `POST /policies/{id}/run` | Run the policy now | Runner |
| `POST /policies/import` | Import a policy export (creates or updates) | Editor |
| `GET /reports/{policy\|system}` | Saved reports | Viewer |
| `GET /reports/{kind}/{id}` and `…/pdf` | A saved report, as JSON or PDF | Viewer |
| `POST /reports/{policy\|system}` | Save a report now: `{"policy_id": N}` / `{"system_id": N}` | Runner |
| `GET /audit-log` | The audit log (`?since=`, `?action=`) | Admin |

Compliance comes from the same calculations as the report pages, PDFs and
saved reports, so the API never disagrees with what you see in OpenSCM.

Every change made through the API is recorded in the audit log under the
token's owner, marked `"via": "api"` with the token's name.

---

## Examples

Each example runs as shown against a server; replace the ids (`7`, `42`) with
yours. The role each needs is in brackets after the title.

### Get every system, page by page (Viewer)

Lists return at most `limit` items (default 100); follow `next_cursor` until
it is `null`:

```bash
cursor=""
while :; do
  page=$(curl -sf -H "$AUTH" "$API/systems?limit=500${cursor:+&cursor=$cursor}")
  echo "$page" | jq -r '.data[] | [.id, .name, .status, .compliance.score] | @tsv'
  cursor=$(echo "$page" | jq -r '.next_cursor // empty')
  [ -z "$cursor" ] && break
done
```

```
1	web-01	active	100.0
2	web-02	active	66.66666666666666
3	db-01	active	100.0
4	web-03	pending
```

One system, as `GET /systems/{id}` and in each list item:

```json
{
  "id": 2,
  "name": "web-02",
  "status": "active",
  "online": true,
  "last_seen": "2026-10-29T19:43:02Z",
  "created_at": "2026-10-20T08:12:44Z",
  "ip": "10.0.1.12",
  "os": "Debian GNU/Linux 12 (bookworm)",
  "arch": "x86_64",
  "groups": [{"id": 1, "name": "web-servers"}],
  "agent": {"version": "0.13.0", "protocol": 1, "upgrade_available": null},
  "compliance": {"score": 66.66666666666666, "tests_passed": 2, "tests_failed": 1, "tests_total": 3},
  "telemetry": {"cpu_usage": 7.5, "mem_used_mb": 812, "mem_total_mb": 3936,
                "disk_used_gb": 9.1, "disk_total_gb": 39.2, "uptime_secs": 1209600}
}
```

Filter with `?status=active|pending` and `?group=<group id>`.

### Approve new systems and put them in a group (Editor)

For provisioning: once a new VM's agent has registered, approve it and place
it, without anyone opening the Pending queue. Only systems whose name matches
what you expect are approved:

```bash
group=$(curl -sf -H "$AUTH" "$API/groups" | jq -r '.data[] | select(.name == "web-servers") | .id')

curl -sf -H "$AUTH" "$API/systems?status=pending" |
  jq -r '.data[] | select(.name | startswith("web-")) | "\(.id) \(.name)"' |
while read -r id name; do
  curl -sf -X POST -H "$AUTH" "$API/systems/$id/approve" > /dev/null &&
  curl -sf -X PUT -H "$AUTH" -H "Content-Type: application/json" \
       -d "{\"groups\": [$group]}" "$API/systems/$id/groups" > /dev/null &&
  echo "approved $name, added to web-servers"
done
```

```
approved web-03, added to web-servers
```

`PUT …/groups` sets the system's **manual** groups to exactly the list given;
`{"groups": []}` removes it from all of them. Automatic groups are left as
they are, and naming one is refused (`400`): their members come from their
rule.
Approving a system that is already active changes nothing.

### Show a system's open findings, with the reason (Viewer)

`GET /systems/{id}/compliance` is the system report: each linked policy and
each test's latest result. A failing result carries the agent's evidence,
saying which condition failed:

```bash
curl -sf -H "$AUTH" "$API/systems/2/compliance" | jq -r '
  .policy_groups[] as $p
  | $p.results[]
  | select(.status == "FAIL" and (.is_excluded | not))
  | "\($p.policy_name): \(.test_name)\n    " + ((.evidence // "[]") | fromjson | map(.note) | join("; "))'
```

```
Linux baseline: SSH: root login disabled
    expected to contain 'PermitRootLogin no' — not satisfied
```

The response, shortened:

```json
{
  "system_id": 2,
  "system_name": "web-02",
  "compliance_score": 66.66666666666666,
  "total_pass": 2, "total_fail": 1, "total_na": 0,
  "policy_groups": [{
    "policy_id": 7, "policy_name": "Linux baseline", "policy_version": "1.2",
    "pass_count": 2, "fail_count": 1, "na_count": 0, "excluded_count": 0, "is_passed": false,
    "results": [{
      "test_id": 11, "test_name": "SSH: root login disabled",
      "status": "FAIL", "is_excluded": false,
      "evidence": "[{\"phase\":\"condition\",\"element\":\"FILE\",\"input\":\"/etc/ssh/sshd_config\",\"selement\":\"CONTENT\",\"operator\":\"CONTAINS\",\"expected\":\"PermitRootLogin no\",\"result\":\"FAIL\",\"note\":\"expected to contain 'PermitRootLogin no' — not satisfied\"}]"
    }]
  }]
}
```

`status` is `PASS`, `FAIL` or `NA`. `evidence` is a JSON array **as a
string** (hence `fromjson` above), and absent when the agent sent none.

### Policy scores for a dashboard, as CSV (Viewer)

```bash
curl -sf -H "$AUTH" "$API/policies" | jq -r '
  ["policy", "version", "score"],
  (.data[] | [.name, .version,
              (if .compliance.score < 0 then "" else (.compliance.score * 100 | round / 100) end)])
  | @csv'
```

```
"policy","version","score"
"Linux baseline","1.2",88.89
"Web server hardening","1.0",""
```

A score of `-1` means the policy has not been scanned yet. `compliance.score`
follows **Settings → Compliance** (by test or by system); `score_by_test`
and `score_by_system` give both. For every system and test result under one
policy, use `GET /policies/{id}/compliance`, the live policy report.

### Scan in CI and fail on a finding (Runner)

```bash
# Queue the policy's tests on its systems
curl -sf -X POST -H "$AUTH" "$API/policies/7/run"
# {"policy_id": 7, "queued": true}

# Agents run them at their next check-in. Wait longer than their heartbeat
# interval (300 seconds by default) before reading the result.
sleep 360

curl -sf -H "$AUTH" "$API/systems/42/compliance" | jq -e '
  [.policy_groups[].results[] | select(.status == "FAIL" and (.is_excluded | not))]
  | length == 0'
```

`jq -e` exits non-zero when the last expression is `false`, so the CI step
fails while the system has an open finding.

### Save a monthly report and download the PDF (Runner)

Saved reports are fixed snapshots, for auditors. From a monthly cron job:

```bash
id=$(curl -sf -X POST -H "$AUTH" -H "Content-Type: application/json" \
          -d '{"policy_id": 7}' "$API/reports/policy" | jq -r .id)
curl -sf -H "$AUTH" -o "linux-baseline-$(date +%Y-%m).pdf" "$API/reports/policy/$id/pdf"
```

`POST /reports/policy` answers `{"id": 1, "kind": "policy"}`. For a single
system, use `/reports/system` with `{"system_id": 42}`. `GET /reports/policy`
lists saved reports, oldest first:

```json
{"data": [{"id": 1, "kind": "policy", "policy": {"name": "Linux baseline", "version": "1.2"},
           "saved_at": "2026-10-29T19:45:07Z", "saved_by": "alice"}],
 "next_cursor": null}
```

### Accept a risk, with the reason (Editor)

Excluding a finding takes it out of the score and records who did it and
why. Put the change ticket in the reason:

```bash
curl -sf -X PUT -H "$AUTH" -H "Content-Type: application/json" \
     -d '{"reason": "Break-glass access, approved in CHG-1042 until 2026-12-31"}' \
     "$API/systems/2/results/11/exclusion"
```

```json
{"excluded": true, "reason": "Break-glass access, approved in CHG-1042 until 2026-12-31",
 "system_id": 2, "test_id": 11}
```

To count it again: `curl -sf -X DELETE -H "$AUTH" "$API/systems/2/results/11/exclusion"`
(answers `204 No Content`).

### Keep policies in git and import them (Editor)

A policy export (**Policies → Export**) is a JSON file you can keep in git
and import on every change, for example from a pipeline on the main branch:

```bash
for f in policies/*.json; do
  printf '%s: ' "$f"
  curl -sf -X POST -H "$AUTH" -H "Content-Type: application/json" \
       --data-binary @"$f" "$API/policies/import" | jq -r '"\(.action) (policy \(.policy_id))"'
done
```

```
policies/web-hardening.json: imported (policy 8)
```

The first import creates the policy (`201`); later ones update the policy
with the same `external_id` (`200`, `"action": "updated"`), so ids stay put
and history is kept. A minimal file:

```json
{
  "format_version": 1,
  "policy": {
    "external_id": "acme-web-hardening",
    "name": "Web server hardening",
    "version": "1.0",
    "description": "Nginx settings for internet-facing servers"
  },
  "tests": [{
    "external_id": "acme-nginx-server-tokens",
    "name": "Nginx hides its version",
    "description": "server_tokens must be off",
    "rational": "Version banners help attackers pick exploits.",
    "remediation": "Set server_tokens off; in /etc/nginx/nginx.conf",
    "severity": "medium",
    "filter": null,
    "app_filter": null,
    "conditions": [{"type": "condition", "element": "FILE", "input": "/etc/nginx/nginx.conf",
                    "selement": "CONTENT", "condition": "CONTAINS", "sinput": "server_tokens off;"}],
    "applicability": [{"type": "applicability", "element": "PACKAGE", "input": "nginx",
                       "selement": "INSTALLED", "condition": "EQUALS", "sinput": "true"}]
  }]
}
```

### Send the audit log to a SIEM (Admin)

The audit log is returned oldest first. This script, run from cron, appends
new entries to a file one JSON object per line (for Splunk, Elastic or
Wazuh to pick up) and remembers where it stopped:

```bash
#!/bin/bash
set -euo pipefail
API=https://your-openscm-server/api/v1beta1
AUTH="Authorization: Bearer $OPENSCM_TOKEN"   # an Admin token
STATE=/var/lib/openscm-siem/last              # "<last id> <its time>"
OUT=/var/log/openscm-audit.jsonl

{ read -r last_id since < "$STATE"; } 2>/dev/null || { last_id=0; since=1970-01-01T00:00:00Z; }
cursor=""
while :; do
  page=$(curl -sf -H "$AUTH" "$API/audit-log?since=$since&limit=500${cursor:+&cursor=$cursor}")
  echo "$page" | jq -c --argjson last "$last_id" '.data[] | select(.id > $last)' >> "$OUT"
  newest=$(echo "$page" | jq -r '.data[-1] // empty | "\(.id) \(.at)"')
  [ -n "$newest" ] && echo "$newest" > "$STATE"
  cursor=$(echo "$page" | jq -r '.next_cursor // empty')
  [ -z "$cursor" ] && break
done
```

One entry:

```json
{"id": 9, "at": "2026-10-29T19:46:24Z", "action": "policy.run",
 "actor": {"id": 1, "username": "alice"}, "target": {"type": "policy", "id": "7"},
 "details": {"via": "api", "token": "runner-token"}, "ip": "203.0.113.7"}
```

`?action=` keeps only actions starting with a prefix, e.g. `?action=auth.`
for sign-ins. `details` is text for most entries and an object for changes
made through the API.

### Upgrade an agent (Admin)

```bash
curl -s -X POST -H "$AUTH" "$API/systems/42/upgrade"
```

`202` with `{"id": 42, "upgrade_to": "0.13.0"}` when queued: the agent
upgrades at its next check-in. `409` when the server has no newer agent for
that system's platform, or the system is not approved. To find candidates:
`GET /systems` and `select(.agent.upgrade_available != null)`.

---

## Python

The same API from Python, with only the standard library. This script lists
every open finding on every active system, follows the pages, and waits when
rate limited:

```python
#!/usr/bin/env python3
"""List every open finding (FAIL, not excluded) across all systems.

Needs only the Python standard library. Set OPENSCM_URL and OPENSCM_TOKEN.
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

API = os.environ.get("OPENSCM_URL", "https://your-openscm-server") + "/api/v1beta1"
TOKEN = os.environ["OPENSCM_TOKEN"]


def call(method, path, body=None):
    """One request; waits and retries when rate limited."""
    data = json.dumps(body).encode() if body is not None else None
    while True:
        req = urllib.request.Request(API + path, data=data, method=method)
        req.add_header("Authorization", f"Bearer {TOKEN}")
        if data is not None:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            if e.code == 429:
                time.sleep(int(e.headers.get("Retry-After", "5")))
                continue
            err = json.loads(e.read() or b"{}").get("error", {})
            sys.exit(f"{method} {path}: {e.code} {err.get('code')}: {err.get('message')}")


def all_pages(path):
    """Every item of a list, following next_cursor."""
    cursor = None
    while True:
        sep = "&" if "?" in path else "?"
        page = call("GET", path + (f"{sep}cursor={cursor}" if cursor else ""))
        yield from page["data"]
        cursor = page.get("next_cursor")
        if not cursor:
            return


for system in all_pages("/systems?status=active&limit=500"):
    report = call("GET", f"/systems/{system['id']}/compliance")
    for policy in report["policy_groups"]:
        for r in policy["results"]:
            if r["status"] == "FAIL" and not r["is_excluded"]:
                why = "; ".join(c["note"] for c in json.loads(r.get("evidence") or "[]"))
                print(f"{system['name']}\t{policy['policy_name']}\t{r['test_name']}\t{why}")
```

```
web-02	Linux baseline	SSH: root login disabled	expected to contain 'PermitRootLogin no' — not satisfied
```

To run a policy from Python: `call("POST", "/policies/7/run")`; to save a
report: `call("POST", "/reports/policy", {"policy_id": 7})`.

---

## PowerShell

```powershell
$Api     = "https://your-openscm-server/api/v1beta1"
$Headers = @{ Authorization = "Bearer $env:OPENSCM_TOKEN" }

# Who am I?
Invoke-RestMethod -Uri "$Api/me" -Headers $Headers

# Every system, page by page
$systems = @()
$cursor  = $null
do {
    $uri  = "$Api/systems?limit=500" + $(if ($cursor) { "&cursor=$cursor" } else { "" })
    $page = Invoke-RestMethod -Uri $uri -Headers $Headers
    $systems += $page.data
    $cursor   = $page.next_cursor
} while ($cursor)
$systems | Select-Object id, name, status, @{n = "score"; e = { $_.compliance.score }} | Format-Table

# Run a policy (Runner token)
Invoke-RestMethod -Method Post -Uri "$Api/policies/7/run" -Headers $Headers

# Save a policy report and download its PDF
$report = Invoke-RestMethod -Method Post -Uri "$Api/reports/policy" -Headers $Headers `
    -ContentType "application/json" -Body (@{ policy_id = 7 } | ConvertTo-Json)
Invoke-WebRequest -Uri "$Api/reports/policy/$($report.id)/pdf" -Headers $Headers -OutFile "report.pdf"
```

`Invoke-RestMethod` throws on an error status; the error body is in
`$_.ErrorDetails.Message`.
