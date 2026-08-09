# LDAP Directories

OpenSCM can delegate user authentication to an external LDAP directory
(OpenLDAP, Active Directory, FreeIPA, 389-DS, etc.) instead of storing every
user's password in the local database. Each tenant can configure one or more
directories; individual users are then marked as either **Local** (password
managed by OpenSCM) or **directory-backed** (password verified by LDAP bind at
login time).

!!! info "Availability"
    LDAP directories are available in **Community Edition (CE)** and
    **Enterprise Edition (EE)**. They are **disabled in SaaS mode** because
    the SaaS server can't reach into customer-internal networks. For SaaS,
    use the upcoming OIDC/SAML SSO integration instead.

---

## Adding a Directory

Navigate to **Settings → Directories** (sidebar, Admin role required) and
click **Add Directory**.

| Field | Description | Example |
| :--- | :--- | :--- |
| **Display Name** | Shown in the Authentication Source dropdown when creating users | `Corp AD` |
| **User Attribute** | LDAP attribute used to look up users by login name | `uid` (OpenLDAP), `sAMAccountName` (AD), `userPrincipalName` |
| **Host** | LDAP server hostname or IP | `ldap.example.com` |
| **Port** | LDAP port — typically `389` for plain LDAP, `636` for LDAPS | `636` |
| **Use TLS (LDAPS)** | Connect over `ldaps://` instead of `ldap://` | enable for production |
| **Skip TLS certificate verification** | Trust the server even with an invalid/self-signed certificate | **only for dev/test** |
| **Base DN** | Subtree under which user lookups happen | `ou=people,dc=example,dc=com` |
| **Service Account Bind DN** | DN used to bind for the initial user search; leave empty for anonymous bind | `cn=openscm,ou=svc,dc=example,dc=com` |
| **Service Account Password** | Password for the bind DN | (managed in OpenSCM DB — see security notes below) |

Click **Save Directory**.

---

## Testing a Directory

Every directory entry has a **Test** button (![test](https://api.iconify.design/fa-solid/plug.svg?width=14){.icon-inline}) — either on the directories list page or inside the edit form. Clicking it runs a service-account bind against the configured server and reports the outcome:

- ✓ **Bind successful** — the server is reachable and the bind DN + password are valid.
- ✗ **Bind failed** — the LDAP error message is shown verbatim (`Connection refused`, `Invalid credentials`, `TLS certificate validation failed`, etc.).

Use the test button after every config change before pointing real users at the directory.

### Common errors

| Error | Likely cause |
| :--- | :--- |
| `Connection refused` | Wrong host, wrong port, firewall blocking |
| `failed to lookup address` | DNS doesn't resolve the host |
| Connection times out (~10 s) | Network unreachable / firewall silently dropping |
| `invalid certificate` / `unknown issuer` | Self-signed cert without **Skip TLS verification** enabled |
| `LDAP bind rejected (rc=49, ...)` | Wrong bind DN or wrong service-account password |
| `LDAP bind rejected (rc=32, ...)` | Bind DN doesn't exist (`No such object`) |

If `nc -vz <host> <port>` from the OpenSCM server succeeds but the Test button doesn't, the issue is usually TLS-related (`use_tls` toggle wrong, or cert verification failing).

---

## Creating Users with Directory Authentication

After at least one directory is configured, the **Add User** form gains an **Authentication Source** dropdown:

- **Local (password stored in OpenSCM)** — the existing behaviour; you set an initial password and the user can change it from their profile page.
- **`<Directory Name>` (LDAP)** — selecting this hides the password field and replaces it with an **External Username** input.

The **External Username** is the value LDAP will match against the configured **User Attribute** under the **Base DN**. Leave it blank to reuse the Login Username — most useful when the two are the same.

### Login flow for directory users

1. User submits their Login Username + password to OpenSCM.
2. Server looks up the user; sees `directory_id` is set.
3. Server connects to the LDAP directory and binds as the **service account**.
4. Server searches under the Base DN for `(user_attribute=<external_username>)`.
5. If exactly one match is found, the server re-opens the connection and **binds as the matched user's full DN** with the password supplied by the user.
6. If the second bind succeeds, the session cookie is issued.

If any step fails, the login is rejected with the same generic message as a wrong local password — no information leak about whether the user exists, whether the directory is misconfigured, or whether the password was wrong.

### Roles are still managed in OpenSCM

The LDAP directory only handles **authentication** (proving who the user is). Authorization — what they can see and do — is controlled by the **Role** dropdown in the user form, exactly the same as for local users. There is no automatic group-to-role mapping in this release; assign each user's role manually when you create them.

---

## Security Notes

- **Bind password is stored plaintext** in the OpenSCM database. The DB file is intended to be protected by filesystem permissions and (in production) full-disk encryption. Field-level encryption of the bind password is a planned hardening follow-up but does not exist in v1.
- **Skip TLS verification** is dangerous — it disables certificate-pinning protections and allows a network attacker to MITM the LDAP traffic. Only enable it on isolated networks where you control both endpoints and where a proper PKI is impractical (typically dev/test labs).
- **All directory operations are audited.** Look for these events in the [Audit Log](admin.md):
  - `directory.create`, `directory.update`, `directory.delete`
  - `directory.test_success`, `directory.test_failure` (with the LDAP error in the details field)
  - `auth.login_success` / `auth.login_failure` already cover the per-user authentication events

---

## Removing a Directory

The **Delete** button refuses if any user still references the directory (with the user count in the error message). To remove a directory cleanly:

1. Edit each user that uses it and switch their **Authentication Source** to **Local** (or another directory) — or delete the user.
2. Once no users reference the directory, the **Delete** button succeeds.

This prevents accidentally locking out an entire fleet of LDAP users by deleting their directory configuration.

---

## Worked example — OpenLDAP

Assume an OpenLDAP server at `ldap.corp.lan` with users under `ou=people,dc=corp,dc=lan` and a service account `cn=svcOpenSCM,ou=svc,dc=corp,dc=lan`:

| Field | Value |
| :--- | :--- |
| Display Name | `Corp OpenLDAP` |
| Host | `ldap.corp.lan` |
| Port | `636` |
| Use TLS (LDAPS) | ☑ |
| Skip TLS verify | ☐ |
| Base DN | `ou=people,dc=corp,dc=lan` |
| Bind DN | `cn=svcOpenSCM,ou=svc,dc=corp,dc=lan` |
| Bind Password | _the service account password_ |
| User Attribute | `uid` |

Then create a user with:

| Field | Value |
| :--- | :--- |
| Login Username | `jdoe` |
| Authentication Source | `Corp OpenLDAP (LDAP)` |
| External Username | _blank — reuses `jdoe`_ |
| Role | `editor` |

At login, OpenSCM will search for `(uid=jdoe)` under `ou=people,dc=corp,dc=lan` and bind as `uid=jdoe,ou=people,dc=corp,dc=lan` with the password from the login form.

---

## Worked example — Active Directory

Assume an AD domain `corp.local` with users under `OU=Users,DC=corp,DC=local` and a service account `svc-openscm`:

| Field | Value |
| :--- | :--- |
| Display Name | `Corp AD` |
| Host | `dc01.corp.local` |
| Port | `636` |
| Use TLS (LDAPS) | ☑ |
| Skip TLS verify | ☐ |
| Base DN | `OU=Users,DC=corp,DC=local` |
| Bind DN | `CN=svc-openscm,OU=Service Accounts,DC=corp,DC=local` (or `svc-openscm@corp.local`) |
| Bind Password | _the service account password_ |
| User Attribute | `sAMAccountName` (or `userPrincipalName` if users log in with UPN) |

Then create a user with:

| Field | Value |
| :--- | :--- |
| Login Username | `jdoe` |
| Authentication Source | `Corp AD (LDAP)` |
| External Username | `jdoe` (or `jdoe@corp.local` if using UPN) |
| Role | `viewer` |

---

## Out of Scope (planned for later releases)

- **Auto-provisioning** — directory users still need to be created manually in OpenSCM with a role assigned. JIT provisioning on first successful bind is a possible future addition.
- **Group → role mapping** — there's no automatic sync from LDAP groups to OpenSCM roles. Assign roles per user.
- **OIDC / SAML SSO** — separate feature tracked in the roadmap; will use browser-mediated federation rather than direct LDAP bind. Suitable for SaaS deployments.
- **Kerberos / GSSAPI bind** — only simple bind is supported in v1.
- **Field-level encryption** of the bind password in the DB.
- **Certificate pinning** beyond the "verify normally / skip entirely" toggle.
