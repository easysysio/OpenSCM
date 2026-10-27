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

| Status | `code` | When |
|---|---|---|
| 400 | `invalid_request` | The request or its body is wrong. |
| 401 | `unauthorized` | No token, or it is unknown, expired or revoked. |
| 403 | `forbidden` | The token's role is too low, or the organization is suspended. |
| 404 | `not_found` | No such record **in your organization**. |
| 409 | `conflict` | Not possible in the record's current state. |
| 422 | `plan_limit` | SaaS: your plan has no room for another system, policy or report. |
| 429 | `rate_limited` | More than 600 requests a minute with this token; see `Retry-After`. |

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

## Example: scan in CI and fail on a finding

```bash
API=https://your-openscm-server/api/v1beta1
AUTH="Authorization: Bearer $OPENSCM_TOKEN"   # a Runner token

# Queue the policy's tests on its systems
curl -sf -X POST -H "$AUTH" "$API/policies/7/run"

# Agents report at their next check-in; then read the result
sleep 600
curl -sf -H "$AUTH" "$API/systems/42/compliance" \
  | jq -e '[.policy_groups[].results[] | select(.status == "FAIL" and (.is_excluded | not))] | length == 0'
```
