# Changelog

All notable changes to OpenSCM are documented here.

---

## [Unreleased]

### Security
- **Cross-tenant data loss via Reset Database (SaaS).** Resetting an organisation ran `DELETE FROM tenant_keys WHERE tenant_id != 'default'` — deleting the agent signing keys of *every other* organisation. The action needs only the **Admin** role, so any customer's administrator could break agent authentication for every other customer on the platform. Single-tenant installations were unaffected, since the statement matched nothing there. The reset no longer touches signing keys at all, and every statement in it is now scoped to the caller's own organisation.
- **Stored cross-site scripting via container names.** The Systems page embedded the container inventory as JSON inside a `<script>` block. JSON does not escape `/`, so a container named `</script>...` closed the block early and the remainder ran as HTML in the browser of anyone viewing that page. Container names come from the agent, so a monitored host could attack the console. Data embedded in script blocks is now escaped so it cannot terminate the block.
- **Destructive actions are no longer performed by following a link.** Deleting a system, user, policy, test, report or enrollment token, approving a pending system, running a policy and clearing notifications were all plain `GET` URLs. Anything that follows a URL could trigger them: a link clicked from another site carried the session, and mail scanners, chat unfurlers and browser prefetchers fetch URLs unprompted — so such a link in an email could delete a system with nobody clicking it. Approving a pending system was the sharpest, admitting an unapproved agent into the fleet in one click. All of these now require a POST.
- **Session cookies are marked `Secure` when the server is configured for HTTPS.** The flag was previously hardcoded off so that plain-HTTP deployments kept working; it is now derived from **app_url**, and the server warns at login when it cannot be set.
- The database reset now binds the organisation identifier instead of interpolating it into SQL.

---

## [0.8.2] - 2026-08-23

### Added
- **Excluding a finding now records why.** Suppressing a result from the compliance score is exactly the change an auditor asks about months later, and until now OpenSCM recorded *who* excluded it and *when* but not *what for*. Clicking exclude now asks for a reason before anything is suppressed, and the reason is shown under the finding on the report, carried into saved report snapshots, and cleared automatically if the finding is put back.

  The prompt is mandatory — an optional field would fill the column with blanks and leave the feature decorative. Exclusions made before this release genuinely have no reason on record and are shown as such rather than being backfilled with invented text.

### Fixed
- **Agent upgrades that appeared to succeed but never took effect.** The server advertised bundled agents using **its own** version rather than the version of the agent it was actually serving. When the two differed, the agent did everything correctly — downloaded the payload, verified its checksum, replaced itself, restarted — and came back reporting the same version as before, so the server offered the upgrade again, indefinitely. Nothing logged an error at any point; every line on both sides reported success.

  The agent now stamps its version into its own binary, and the server reads it back directly — so the version it advertises is measured from the payload rather than assumed. This works identically for every platform and architecture, because finding the stamp is a byte scan rather than executable-format parsing. Bundles that predate the stamp still fall back to the older behaviour, but the server now warns loudly when it does so.

  This only affected installations whose bundled agents differed from the server build — most visibly locally built servers. A stale agent binary that had been committed to the repository is no longer tracked, since CI supplies these at build time.

---

## [0.8.1] - 2026-08-23

### Added
- **A visible button to exclude a finding.** Excluding a result from the compliance score was possible only by **right-clicking** a row on a live report — an action with no on-screen affordance, and one that does not exist at all on touch devices. Each result row now carries a small control in the Status column: 🚫 to exclude, ↩ to put it back. Right-click still works.

  It appears exactly where the action was already permitted — Editors and above, on live reports only, for results that were actually scanned — and never on saved report snapshots, which stay frozen.
- **`install.sh`** — a one-command agent installer at `https://repo.openscm.io/install.sh`. Detects the OS and CPU, installs `scmclient` with your own package manager, writes the config pointed at your server, and starts the service. `--token` for enrollment-token rollouts, `--uninstall` (with `--purge`) to remove it again, `--dry-run` to see everything it would do first.

### Changed
- **SaaS: the organization name has moved to the right of the top bar**, next to the user menu, instead of trailing the Home / Systems / Policies / Reports links.

---

## [0.8.0] - 2026-08-21

### Added
- **Guided first run.** A new install shows an empty dashboard and nothing on screen says that the order is *register a system → write a test → build a policy → run it*. First-time users now get a short walkthrough on the dashboard naming those four steps, each with a diagram of what it means and a link straight to the page that does it. The agent step shows the real install and configuration commands with your server URL filled in (set **app_url** under Settings for this) and covers approving the system afterwards, and the whole thing is dismissible with **Don't show this again**.

  It appears **only on the dashboard** — never over a page you are working on — and only for roles that can act on it: Viewers do not see it at all, and Runners get the three screens that concern them rather than authoring steps they would be denied at. Closing with Esc or the X does *not* dismiss it permanently, so an accidental close on step 2 does not bury something unread. **Quick start** in the user menu reopens it at any time.

  Upgrading does not show it to anyone who already uses OpenSCM — only to accounts created from here on, and to the administrator of a fresh install.

### Changed
- **PDF reports are now roughly 25× smaller.** A two-page report was 2.7 MB and a seven-page one barely larger, because the old renderer embedded four complete font faces in every document regardless of what the report actually used. Fonts are now subsetted, so the same reports are 48 KB–130 KB. This matters most for the **Email me the PDF** flows, where every report sent was carrying ~2.6 MB of unused font data and edging towards the attachment limits some mail gateways enforce.
- **Table headers now repeat on every page** of a multi-page findings table. Previously only the first page was labelled, so from page 2 onwards an auditor had unlabelled columns.
- Reports use slightly tighter table rows and so run to fewer pages for the same content. No content has been removed.

### Security
- **Closed RUSTSEC-2026-0187 and six unmaintained-crate advisories** by replacing the PDF renderer. All seven traced to a single root: `genpdf`, unmaintained since 2021, which pinned `lopdf` 0.26 and `image` 0.23. The advisory needed `lopdf` ≥ 0.42 and no version bump could reach it — the maintained `genpdf` fork only gets to 0.31 — so closing it meant replacing the renderer. The project now uses `printpdf` 0.12 (`lopdf` 0.44) with an in-tree layout layer, and `cargo audit` reports **zero findings** with the previous suppression removed rather than merely re-ignored.

  The exposure was always latent rather than live — the advisory requires *parsing* a hostile PDF and this product only ever generates them — but it sat in every dependency scan a prospective customer might run.

---

## [0.7.14] - 2026-08-20

### Added
- **SaaS: automatic cleanup of abandoned signups.** **Settings → SaaS → Dormant Organizations** adds two independent rules, both **off by default**:
  - **Unverified registrations** whose email address was never confirmed are **deleted** after a set number of days. Nothing can exist behind them — the account cannot be signed into until the address is verified — and they are not warned first, because the only address on file is the unverified one, usually a typo.
  - **Verified organizations that never enrolled a system** are acted on after a set number of days, and *what* happens depends on what they hold. An account with **nothing** — no policies or tests it authored, no compliance history, no saved reports — is **deleted**. One that holds any of those is only **suspended**, so authored work and audit evidence are never destroyed; a superuser can reactivate it unchanged. Admins are emailed once beforehand and the mail states plainly which of the two will happen.

  An organization with systems is never a candidate, `platform` and `default` are excluded outright, both outcomes are audited (deletions into the platform log, since a tenant's own log is removed with it), and a warning is only recorded as sent once the mail has actually left, so an SMTP outage retries rather than skipping straight to the action.

### Fixed
- **Tenant suspension is now actually enforced.** Login checked that the organization *existed* but never looked at its status, so the admin **Suspend** button set a flag that nothing read — a suspended organization could still sign in and use the product normally. Suspended organizations are now refused at login.
- **The Policy Store is now visible to Viewers, and therefore while viewing a tenant read-only.** Browsing the catalogue required the Editor role, so it was hidden both from ordinary Viewers and from a superuser using **View as tenant** — where "which policies does this customer have, and are any behind?" is one of the main questions that view exists to answer. The listing now requires only Viewer; **installing and updating still require Editor**, and the install buttons are hidden from anyone who cannot use them. Nothing new is exposed: the catalogue is already served publicly and unauthenticated, and which policies a tenant has installed is already on their policies page.


---

## [0.7.13] - 2026-08-20

### Added
- **SaaS: superusers can view a tenant's data read-only.** A **View as tenant** button on the tenant admin page switches the session to that tenant, so every existing page — systems, policies, tests, reports, compliance trends — shows what the customer sees. Support work on a multi-tenant product is otherwise guesswork.

  The access is deliberately narrow: **read-only**, enforced twice over. The session role is forced to `viewer` on every request rather than trusted from the cookie, so the ordinary permission checks reject anything privileged; and a middleware independently rejects every non-GET request while impersonating, so a mutating GET route — or a handler added later that forgets its permission check — still cannot write into a customer's tenant. Nesting is refused, the session expires after an hour, and a red banner naming both tenants sits on every page.

  Entering and leaving are recorded in **both** audit logs, attributed to the real operator — so a customer can see in their own log that someone looked.


---

## [0.7.12] - 2026-08-19

### Security
- **Dependency advisories are now checked on every push, and the first sweep cleared eight of nine.** `cargo audit` runs in CI (advisory-only for now, so a newly published CVE cannot wedge a release) and Dependabot is configured for **security updates only** — no routine version-bump PRs, so `Cargo.lock` stays reproducible.
  - Refreshing the lockfile within existing version constraints resolved **RUSTSEC-2026-0204** (`crossbeam-epoch`, invalid pointer dereference) and one of the two **RUSTSEC-2026-0258** (`h2`) instances.
  - Dropped the unused sqlx `macros` feature, which pulled in the MySQL and Postgres drivers this SQLite-only product never loads — removing 13 crates and with them **RUSTSEC-2023-0071** (`rsa`, Marvin timing sidechannel), an advisory with no upstream fix. Recorded in `.cargo/audit.toml` since the crate is still resolved-but-unbuilt.
  - **Upgraded `reqwest` 0.11 → 0.13 and `ldap3` 0.11 → 0.12**, which moves the TLS stack to `rustls 0.23` / `rustls-webpki 0.103` and closes the three certificate-validation advisories (**RUSTSEC-2026-0098**, **-0099**, **-0104**) plus **RUSTSEC-2026-0258** (`h2`) and **RUSTSEC-2025-0009** (`ring 0.16`). Both crates select rustls' **ring** provider rather than the new aws-lc-rs default, which requires cmake and a C toolchain and does not cross-compile to the riscv64 / loongarch64 / s390x / powerpc64 targets this project ships; the provider is installed explicitly at startup, and verified with a live HTTPS request.
  - **One advisory remains:** **RUSTSEC-2026-0187**, a stack overflow in `lopdf` reached through `genpdf`, which is at its latest release and effectively unmaintained. It requires a hostile PDF as *input*; this product only generates them. Closing it means replacing the PDF library.


### Fixed
- **Windows builds no longer warn about unused code.** The `boolean()` helper is only called from the Unix path-permission checks, so on Windows it had no users and every build reported it. Gated to match its callers.


---

## [0.7.11] - 2026-08-19

### Fixed
- **Agent: repeated commands now run once per scan.** A policy commonly asks the same command several different questions — the CIS Debian profile runs `sshd -T` twenty times to check twenty sshd settings — which meant 84 process spawns per scan where 60 would do, and `sshd -T` is among the more expensive things to spawn. Results are cached for the duration of a scan and cleared at the start of the next, so a remediation applied between two scans is still picked up immediately.
- **Agent: memory growth on hosts with many processes.** `collect_system_info` called `System::new_all()` and then `refresh_all()`, walking every process on the host twice per heartbeat while reading only CPU and memory totals. On a container host that covers every process in every container — they share the host PID namespace — so it built and discarded thousands of process structs every 300 s. The client is a static musl binary and musl's allocator returns little of that to the OS, so it accumulated as RSS: one agent reached **2.9 GB after a week**, with 43 minutes of CPU burned doing it. Telemetry now refreshes CPU and memory only, and the `PROCESS` element no longer loads command lines, environments, cwd and disk usage for fields it never reads. Restart the agent once after upgrading to reclaim memory already held.
- **Agent service is now memory-capped** (`MemoryHigh=256M`, `MemoryMax=512M`). The agent's working set is tens of MB; a monitoring agent should never be able to pressure the workloads it monitors.

### Added
- **Tests run in CI on every push, and releases are gated on them.** Neither workflow ran `cargo test` — they built straight from a tag, which is how 0.7.4 shipped a template that crash-looped the server on boot. The release pipeline now depends on the suite passing before anything is built or published. Fixing `schema_migration.rs` was a prerequisite: it tested the v3 → v4 migration against a four-table fixture and had been failing since roughly v5, unnoticed because nothing ran the full suite. Its assertions are replaced with invariants that survive schema growth, including one that re-runs every migration over an existing schema to prove each step is guarded.
- **`release.sh`** cuts a coordinated CE + SaaS release: both versions, both changelogs, the docs version strings and the SaaS `CE_TAG`, in one step. It refuses to run on a dirty tree, an existing tag, an empty `[Unreleased]`, or a failing test suite.

### Changed
- **CE and SaaS now share a version number.** Every SaaS release exists to pick up a CE release, and the patch numbers had tracked CE exactly for ten consecutive releases — so the separate SaaS `0.5.x` line carried no information, just a translation step in every changelog and a third number to keep aligned with `CE_TAG` (the drift that shipped stale CE code in 0.3.2–0.3.4). SaaS jumped `0.5.11` → `0.7.11` to match, and `release.sh` takes a single version argument instead of two.
- **CI installs `cargo-zigbuild` and `nfpm` prebuilt instead of compiling them.** Every job rebuilt both from source before building anything — roughly 13 identical from-source builds per release once the 8-target client matrix is counted. `apt-get update` is also now conditional on `envsubst` being absent, since the Azure Ubuntu mirror routinely stalls it for minutes.
- **The openscm.io documentation now lives in this repository** (`docs/` + `mkdocs.yml`), so a feature and its documentation land in the same commit. It had drifted six releases behind. `deploy-docs.sh` builds from a sparse checkout and swaps the published site atomically.


---

## [0.7.10] - 2026-07-25

### Changed
- **UI performance: a typical page now transfers ~290 KB instead of ~4.8 MB, and almost nothing on repeat visits.** Every page previously pulled 4,847 KB of vendor JS/CSS across 31 files, uncompressed and uncacheable. Four independent fixes:
  - **Static assets are now cacheable.** They were served with no validator, so browsers re-downloaded everything on every navigation. Assets now carry an `ETag` (scoped to the build version) and `Cache-Control: max-age=3600`, and conditional requests get a `304` — repeat navigations transfer a few hundred bytes. The short max-age plus a version-scoped ETag means an upgrade still picks up new assets rather than pinning stale ones.
  - **Responses are compressed** (gzip/brotli, negotiated per request). Worth ~82% on the remaining assets and on the large HTML report tables.
  - **Unused libraries removed.** jQuery UI (252 KB, loaded only for an AdminLTE shim that guards against a clash which cannot occur once jQuery UI is gone), InputMask (100 KB) and Moment.js (60 KB) were on every page and referenced by nothing. The external Ionicons CDN stylesheet is also gone — no `ion-*` icon is used, and dropping it removes a third-party request per page load (which also blocked page render on air-gapped installs).
  - **Heavy optional libraries are now opt-in per page.** `jszip`/`pdfmake`/`vfs_fonts` (2.2 MB) load only on the five pages with Excel/PDF table buttons; Chart.js only on the dashboard and the two live report pages; Select2 and Duallistbox only on the form pages that use those widgets. Beyond bandwidth this removes the JS parse cost on every other page.

  Net: a baseline page goes from **4,847 KB / 31 files** to **1,954 KB / 19 files**, or **~290 KB** on the wire once compressed — then near-zero on subsequent navigations.

---

## [0.7.9] - 2026-06-16

### Fixed
- **"Nothing queued — this policy does not apply to this system" when running a policy that clearly does apply.** The per-policy **Run** button reported the row count from its `INSERT OR IGNORE`, which is **0 when the tests are already queued** — e.g. clicking Run twice, or running a policy whose scheduled scan is still pending the agent's next check-in. That legitimate case was misreported as the policy not covering the host. Applicability is now counted separately from the insert, so Run reports the policy's applicable tests whether or not they were already queued; a genuinely uncovered system still reports that correctly.

---

## [0.7.8] - 2026-06-16

### Added
- **Click a PASS / FAIL / NA / EXCLUDED count to filter the report to those elements.** On the system and policy compliance reports — **live and saved/archived (Reports menu)** — the status counts in each card header are now clickable: click **Failed** to show only that card's failing tests, click again (or another status) to change or clear the filter. Scoped per card so each policy (system report) or system (policy report) filters independently. Purely client-side — no reload. On the system report, `NOT_SCANNED` rows fall under the NA filter to match that report's NA count.

---

## [0.7.7] - 2026-06-16

### Added
- **Run a single policy on a single system, from the system report.** Each policy card on the system compliance view gains a **Run** button that queues just that policy's tests for just that host — so after fixing a finding you can re-check the one machine instead of rescanning the fleet. Requires the Runner role; the action is audited (`policy.run_on_system`). Scans are queued to the agent, so results land on its next check-in rather than instantly, and the confirmation message says so. Requesting a policy that doesn't cover the system queues nothing and reports that, rather than a silent success.

### Fixed
- **Data loss: a long server outage no longer deletes every system on restart.** With `auto_prune_inactive` enabled, the prune deleted any active system whose `last_seen` was older than the threshold — but while the server is down no agent *can* report, so after an outage longer than the threshold the whole fleet looked inactive and was wiped on the first 60-second tick, before any agent had a chance to check in. The prune is now gated on **server uptime**: a tenant is skipped until this server process has been running at least as long as its own threshold, so a stale `last_seen` can no longer be confused with "the server wasn't there to hear it". Genuinely absent systems are still pruned once that window has passed. Covered by regression tests.

---

## [0.7.6] - 2026-06-16

### Fixed
- **Agent (`scmclient`): stop duplicate/orphaned agents from piling up.** Field hosts accumulated dozens of stray `scmclient` daemons over successive self-upgrades (an older restart path spawned a detached copy instead of replacing the process), and some grew to multi-GB RSS. The agent now takes a **single-instance advisory lock** (`scmclient.lock`, next to the config) at startup in daemon mode; a second instance logs and exits instead of running in parallel. The lock is `O_CLOEXEC` (Rust default), so it releases across the upgrade `exec()` and the re-exec'd binary re-acquires it cleanly — no self-deadlock. The `run` / `--help` / `--version` one-shots are unaffected.
- **Agent memory: switched to a single-threaded Tokio runtime.** The agent is a strictly sequential heartbeat loop but ran on the multi-threaded runtime, whose per-worker glibc malloc arenas never return freed memory — long-lived agents ballooned to multi-GB RSS / 20-GB VSZ. `current_thread` uses one arena, so memory plateaus low and flat. No functional change.
  - *Operators:* existing strays are detached from the service manager, so upgrading won't clear them. Clear once with `systemctl stop scmclient && pkill -x scmclient && systemctl start scmclient` (adjust the unit name).

---

## [0.7.5] - 2026-06-16

### Fixed
- **Compliance-trend charts now plot the hourly axis in the viewer's browser timezone.** The 0.7.4 timezone work converted `.datetime` HTML elements, but the trend charts (dashboard fleet trend + system/policy report trends) render their X-axis from server-side bucket labels, which stayed in UTC. The hourly range — the only one with a clock — is now shifted to local time client-side (e.g. a `09:00` UTC point shows as `12:00` in GMT+3); daily/weekly/monthly/yearly are date-only and unchanged.

---

## [0.7.4] - 2026-06-16

### Changed
- **All timestamps in the web UI now render in the viewer's browser timezone.** Previously times were shown inconsistently — some as raw UTC, some as the server's local time. The server now emits every displayed timestamp as canonical UTC, and a single shared converter (`base.html`) localizes every `.datetime` element to the browser's zone, appending the zone abbreviation (e.g. `15/06/2026, 17:30:00 GMT+3`). Covers systems, audit log, reports (live, saved, and diffs), containers, enrollment tokens, and the active-key timestamp. The per-page duplicate converters were removed in favor of the shared one.

### Added
- **`templates_parse` smoke test** that parses every embedded Tera template, so a template syntax error fails the build instead of crash-looping the server at startup.

---

## [0.7.3] - 2026-06-12

### Added
- **Hourly / Daily / Weekly / Monthly / Yearly ranges on the system and policy trend charts.** The Compliance Trend card on the live report pages gains the same range selector as the dashboard's fleet trend (`?range=`, default Hourly = last 24 hours; Daily = last 30 days; Weekly/Monthly = last 12; Yearly = last 10). Buckets average their hourly snapshots — score and the tooltip's pass/fail tallies alike. The card now shows from the **first** snapshot (previously hidden until two existed), so switching to a sparse bucket can't hide the selector, and it can be **collapsed** with the same minimize control as the dashboard's trend card.

### Fixed
- **Container compliance percentages are now rounded to 2 decimals.** The stored per-container score and the policy-level container axis (`policies.score_container`) were written as raw SQL division results, so the report badges and the container detail page showed values like `66.66666666666667%`. Both are now `ROUND(…, 2)` at the source; existing stored values are rewritten on the first recalculation after upgrade.

---

## [0.7.2] - 2026-06-09

### Added
- **Per-system and per-policy compliance trends.** The system and policy live report pages gain a **Compliance Trend** chart showing the entity's hourly history (design: `docs/design/0.7.2-entity-trends.md`). A new `entity_compliance_history` table records one snapshot per scanned system and policy every hour, carrying **both** compliance axes — so flipping a Per-test / Per-system / Per-policy toggle re-renders the whole line with no artificial step (the 0.6.6 dual-mode approach). Not-scanned entities are skipped (gaps render as gaps); tooltips show each snapshot's pass/fail tallies; the card hides until 2+ points exist. **Schema v36 → v37.**
- **Two trend retention settings** (Settings → General): **System/Policy Trend Retention** (default 90 days — high-volume, per-entity hourly rows) and **Compliance Trend Retention** (default 365 days), both pruned in the daily retention pass with `retention.*` audit rows, `0` = keep forever. Note: the fleet-wide dashboard trend (`compliance_history`) was previously kept forever — existing installs start trimming it to 365 days on upgrade; set `0` to restore the old behaviour.

---

## [0.7.1] - 2026-06-09

### Fixed
- **Database errors in report/list sub-queries are no longer silently swallowed.** Eight query sites used `unwrap_or_default()` on a fetch, so a DB error (e.g. a missing column on a partially-migrated database) rendered an empty section with no trace — the same failure class that hid the 0.7.0 Systems-page container-list bug. They now log the error and degrade to the same empty fallback: test add/edit condition lists, the Systems-page agent-package lookup, per-system and container-detail container results, and the container attach in live/PDF policy reports and saved snapshots.

---

## [0.7.0] - 2026-06-08

### Added — Containers: finished the implementation
- **Per-container compliance is now its own axis.** Container test results no longer distort host/system/policy/test scores. Every host-axis aggregation (`update_test_stats`, `update_system_stats`, `update_policy_stats`) counts only host-level results (`results.container_id = 0`), and a new `update_container_stats` pass scores each container from its own results (`container_id = containers.id`). **Schema v34 → v35** adds `containers.tests_passed` / `tests_failed` / `compliance_score` (populated on the first recalc after upgrade).
- **Reports now show per-container results, nested under each host.** The live policy report, live system report, and archived snapshots break out each container with its own pass/fail/score and per-test rows (including the evidence "why?" panel), instead of folding container results into the host grid or dropping them. Pure-container policies (e.g. CIS Docker) show a real headline via a new stored `policies.score_container` axis instead of "Not Scanned." The policy list honours the same fallback.
- **Container detail panel.** New `GET /systems/{id}/containers/{cid}` page shows a container's identity, full configuration metadata (privileged, run-user, network mode, ports, mounts, read-only FS, restart policy, health check), its compliance score, and its recent per-container test results with the evidence panel. Reachable from a "Full Detail & Test Results" link in the Systems-page container modal.
- **Run commands inside containers with the new `EXEC` element.** A container-only element (alongside IMAGE, PRIVILEGED, …) that runs a command inside each container via `docker exec` / `podman exec` and tests its `OUTPUT` or `EXIT CODE` — the container-side counterpart to the host-only `CMD`. Like the other container elements, it **fans out per container automatically** (the element type decides where it runs — no host/container selector), requires the agent's `cmd_enabled = true`, and FAILs with a clear log on no-shell images (scratch/distroless). Non-container elements (FILE, PACKAGE, CMD, …) return NA inside a container rather than misreporting the host. **Schema v35 → v36** seeds the `EXEC` element on existing databases. The canned `cis-container-config-l1` policy gains an EXEC check (CIS Docker 5.6 — SSH not running in the container).

---

## [0.6.6] - 2026-06-08

### Changed
- **Compliance toggles now switch instantly, and the trend chart no longer jumps when you switch.** Building on the two compliance toggles from 0.6.5: every recalc now computes *and stores* **both** the per-test and per-(system|policy) score for every policy (`policies.score_test` / `score_system`), system (`systems.score_test` / `score_policy`), and history snapshot (`compliance_history.{systems,policies}_score_{test,system|policy}`).
  - **Instant table switch.** The dashboard top-5, policy list, and (live) policy/system reports read the stored column matching the current mode — so flipping a toggle and refreshing shows the new numbers **immediately, with no recompute** (previously the dashboard/list waited for the ~minute background recalc).
  - **No artificial jump in the trend.** Because both scores are recorded in every hourly snapshot, the compliance trend chart re-draws the **entire history** in whichever mode you pick, instead of showing a step at the moment you changed the setting. (History snapshots recorded *before* the upgrade carry a single recorded value, shown in either mode; points recorded after the upgrade carry both.)
  - **Fixed:** the policy list previously computed per-system compliance inline, ignoring the toggle entirely — it now honours the setting like every other surface.
  - **Fixed: the trend chart no longer reads as flat-zero after upgrading.** The new history columns were added with a `0` default and not backfilled, so every *pre-upgrade* snapshot read 0 in the new columns and the trend collapsed to zero. A backfill copies each old snapshot's recorded value into both mode-columns (legacy `systems_score`/`policies_score` were preserved all along), restoring the historical line. Post-upgrade snapshots are untouched.
  - **Schema v32 → v34** — v33 adds the dual-score columns to `policies`, `systems`, and `compliance_history`; v34 backfills the history columns from the legacy scores (pre-upgrade rows only, idempotent).

---

## [0.6.5] - 2026-06-07

### Added
- **Two independent compliance-calculation toggles** (Settings → Compliance, per-tenant) — one for how a **policy's** score is computed and one for how a **system's** score is computed. They're separate aggregations (a policy aggregates over its *systems*; a system aggregates over its *policies*), so each gets its own choice:
  - **Policy Compliance — Per test / Per system**
    - *Per test* (default): `total PASS ÷ (PASS + FAIL)` across the policy's systems — moves smoothly with remediation.
    - *Per system*: `compliant systems ÷ scanned systems`, where a system counts only if **all** its tests pass — the audit view (pre-0.6.5 behaviour).
  - **System Compliance — Per test / Per policy**
    - *Per test* (default): `total PASS ÷ (PASS + FAIL)` of the system's own checks.
    - *Per policy*: `passed policies ÷ applicable policies`, where the system fully passes a policy only with no failing test — so **one assigned policy with any failing test → 0%** (your scenario), not partial test credit.

  The modes genuinely diverge: a fleet where every host has one stray failing check reads **~95% per test** but **0% per system/policy**. Splitting into two toggles lets you score policies and systems differently if you want (e.g. policies per-test for remediation tracking, systems per-policy for a strict host verdict).
  - **Applied consistently across every surface.** Policy side: `update_policy_stats` (dashboard top-5 + policy list), the live policy report, and the archived/saved policy report (view + PDF). System side: `update_system_stats` (systems list + dashboard) and the live + saved system reports (recomputed on view). Each mode is read per-tenant via a correlated settings lookup, so a mixed-mode multi-tenant fleet is handled in a single recalc statement.
  - The dashboard "Pass/Fail" counts follow the policy mode (total PASS/FAIL tests vs compliant/failed systems). Stored in `systems_passed`/`systems_failed`; names retained for schema stability, header is the generic "Pass/Fail".
  - Switching either toggle signals a recompute (dashboard/lists update on the next sync); reports re-derive the % on each view, so they — including archived ones — reflect the current settings immediately. **No schema change.**
  - The per-system **COMPLIANT / NON-COMPLIANT** badge is unaffected by either toggle (a system is "compliant" only if it has no failing tests); only the *percentages* change. NA and excluded results stay out of both numerator and denominator in every mode. A shared `compliance_pct(binary, units)` helper backs all four computations; 6 unit tests pin both formulas including the divergence and single-failing-unit cases.
  - NA and excluded results stay out of both numerator and denominator in both modes (unchanged). 5 unit tests pin the two formulas, including the divergence case.

---

## [0.6.4] - 2026-06-07

### Added
- **Test result evidence — "why did this client fail this test?"** A result is no longer just `PASS`/`FAIL`/`NA`: the agent now ships a per-condition breakdown showing exactly which condition(s) failed and what was expected. Both the system report and the policy report gain a **"why?"** toggle on failed and NA rows that expands a per-condition table — element / parameter / sub-element, the expected operator+value, the per-condition verdict (failing ones highlighted), and a short note. **NA is explained too** — applicability misses show up as `applicability` rows ("applicability condition not met"). Full design in `docs/design/0.6.4-evidence.md`.
  - **Privacy: match-only, never raw content.** Evidence carries only the admin-authored test spec (element, parameter, operator, expected value), the verdict, and a generic note — e.g. `"expected to contains 'PermitRootLogin no' — not satisfied"`. It never includes host-observed content (file bytes, command output, hashes), so secrets can't leak into the DB or a report.
  - **Built in the caller**, not the evaluator: assembled from the per-condition results the agent already collects, so the ~30 evaluator arms are untouched and verdict logic is unchanged. New `compliance::build_evidence` + `ConditionOutcome`.
  - **Schema v31 → v32** — `results.evidence TEXT` (nullable). Fully back-compat: pre-0.6.4 agents omit evidence, old servers ignore the field, old result rows just show no "why?" toggle. Agent-side capture requires agents on 0.6.4.

### Changed
- **SaaS platform settings moved to their own "SaaS" tab.** The `notify_new_tenant` toggle introduced in 0.6.3 lived in a card at the bottom of the Email tab; it now has a dedicated **SaaS** tab in Settings (between Email and Danger Zone), gated on `is_saas and is_superuser` so it appears only in the SaaS edition for superusers and renders nothing in Community Edition. Same setting, same storage (`notify_new_tenant` under the `default` tenant) — purely a UI relocation, so existing values are unaffected. Gives the SaaS-only settings a clear home to grow into.

---

## [0.6.3] - 2026-06-02

### Added
- **SaaS Platform settings section (SaaS edition only).** The Settings → Email tab now shows a "SaaS Platform" card in SaaS mode (superuser-only, gated on `is_saas`), with a toggle: **Email superusers when a new tenant self-registers**. Stored as the global `notify_new_tenant` setting under the `default` tenant, persisted by the existing `settings_save` flow (routed to `default` like the SMTP keys). The section renders nothing in Community Edition. Defaults to enabled, preserving the behaviour shipped to SaaS in 0.4.3. The actual notification email is sent by the SaaS binary; this is just the shared settings UI + storage that drives it.

---

## [0.6.2] - 2026-06-02

### Fixed
- **Inventory now clears when the *last* running container stops (follow-up to 0.6.1).** 0.6.1 switched the agent to enumerate running containers only, which exposed a latent signalling bug: the agent collapsed "no containers found" to `None` (`if discovered.is_empty() { None } else { Some(...) }`), and the server treats `None` as *"agent sent no container info — leave existing rows alone."* So once the last container stopped, the agent reported `None`, the server skipped the prune, and the old rows lingered (the exact symptom: `docker ps` empty but the Systems view still showed containers). The agent now sends the correct three-way signal, computed in `containers::enumerate()` which returns `Option<Vec>`:
  - `Some([])` — a container runtime **is** present but has **zero running containers** → the server prunes all of the host's rows. **This is the case that was broken.**
  - `Some([…])` — the current running set → upsert + prune stragglers.
  - `None` — no runtime installed, non-Linux, **or the runtime's `ps` failed** (daemon down / no permission) → the server leaves rows untouched, so a transient daemon outage never wipes a host's inventory.
  - The daemon-down distinction is new: `enumerate_runtime` now returns `None` on command failure (vs an empty list on success), so "runtime broken" is never mistaken for "zero containers."

  **Agent-side fix — redeploy / auto-upgrade agents to 0.6.2.** Lingering rows clear on the first heartbeat after the agent is upgraded. No server change.

---

## [0.6.1] - 2026-06-02

### Fixed
- **Stopped containers are now removed from the inventory.** The Linux agent enumerated containers with `docker ps -a` / `podman ps -a`, where `-a` includes **stopped / exited** containers. A stopped container therefore kept appearing in every heartbeat report, so its `last_seen` never went stale and the server's straggler-prune (which deletes any container missing from the latest report) never removed it — it lingered in the Systems-list container view indefinitely until `docker rm`. The agent now runs plain `ps` (running + paused only), so stopping a container drops it from the next report and the existing server-side prune clears it on the following heartbeat. **Agent-side fix — redeploy / auto-upgrade agents to pick it up;** no server change. Per-container compliance evaluation is unaffected (it only ever assessed live containers).

---

## [0.6.0] - 2026-06-02

**Golden enrollment tokens — auto-approve enrolling systems without the UI.** An admin mints a token, drops it in the agent config, and every system that enrolls with it comes up `active` instead of `pending` — no manual Approve click. Combined with automatic groups (0.5.2), a freshly-provisioned box goes from install → approved → grouped → scanned with zero human steps. Full design in `docs/design/0.6.0-enrollment-tokens.md`.

### Added
- **Enrollment-token management on the Systems page** (`/systems/tokens`, Admin-gated, linked from the Systems header). Create a named token with an optional **expiry** and optional **max-uses**; the raw secret is shown **once** in a copy box and never again. List shows each token's display prefix, status (Active / Disabled / Expired / Used up), expiry, `use_count / max_uses`, and last-used time. Enable/disable toggle and delete. Every create/enable/disable/delete is audited.
- **Agent config field `[server] enrollment_token`** (TOML) / `EnrollmentToken` (Windows registry). Sent **only at first registration**, never on routine heartbeats, so the secret isn't repeatedly transmitted once the system has an ID.
- **Auto-approval at registration.** When a valid token is presented, the server brings the system up `active` and records the token use (`use_count++`, `last_used_at`) atomically inside the registration transaction. A system that enrolled *before* a token was minted is promoted from `pending` to `active` if it re-registers presenting a now-valid token.

### Security
- **Approval bypass, not auth bypass.** The token only sets the new system's initial status — it does **not** weaken agent authentication. The ed25519 keypair handshake and per-request signature verification are unchanged. A leaked token can only auto-approve a system an attacker could already enroll as pending; it can't impersonate an existing system or forge results. Exposure is bounded by expiry, max-uses, and revocation.
- **Secrets hashed at rest.** Only `SHA-256(token)` is stored; a DB leak yields hashes, not usable tokens. A non-secret display prefix (`oscm_` + 7 hex) is stored for identification.
- **Lenient invalid handling.** A typo'd, expired, or disabled token never blocks enrollment — the system simply lands `pending` for manual approval, and the bad attempt is audited as `enrollment.token_rejected` (warn). No 403, no lost system.
- **Approval-only.** A token does not assign groups; placement is left to automatic groups, which sort the now-active system on its first heartbeat.

### Database
- **Schema v30 → v31** — adds the `enrollment_tokens` table (`token_hash`, `token_prefix`, `enabled`, `expires_at`, `max_uses`, `use_count`, `created_by`, `last_used_at`) + lookup index. New table only; enrollment behaviour is unchanged until an admin mints a token. Fresh installs get it in `initialize_database`.

### Fixed
- **Windows agent: `PsEnabled` and the new `EnrollmentToken` registry values are no longer pruned as stale.** `EnrollmentToken` was added to the registry-key allowlist (`PsEnabled` was already written/read but missing from the allowlist — a latent bug that would delete the PowerShell-enabled setting on every config load; corrected in passing).

---

## [0.5.4] - 2026-06-02

**Two database performance fixes surfaced by sqlx slow-statement logging on a production SaaS instance.** Neither was a regression — both are pre-existing costs that grew with data volume — but both are cheaply fixable. Schema v30 (index-only).

### Fixed
- **Auto-prune of inactive systems is now sargable (was a full scan every 60 s).** `prune_inactive_systems` (scheduler TASK B, runs once per minute) computed `(strftime('%s','now') - strftime('%s', last_seen)) > ?` **per row**, which is non-sargable — no index on `last_seen` could be used, so every tick scanned the full set of a tenant's active systems (observed at ~1.1 s even when deleting zero rows). The cutoff timestamp is now computed in Rust and the query filters `last_seen < ?`, which combined with the new `idx_systems_prune (tenant_id, status, last_seen)` is a range scan. Semantics are identical (`now − last_seen > N·60s` ⟺ `last_seen < now − N min`); SQLite's `CURRENT_TIMESTAMP` format sorts chronologically as a string so the comparison is correct.
- **Compliance recalc gets a covering index.** The `update_test_stats` correlated subqueries (`UPDATE tests SET systems_passed = (SELECT COUNT(*) FROM results …)`) filter results on `(tenant_id, test_id, result, excluded)` and join `systems` on `system_id` — none of which the existing `idx_results_tenant_test (tenant_id, test_id)` fully covered, so each per-test COUNT did heap fetches (observed at ~1.0 s for 651 tests on the startup global recompute). New `idx_results_recalc_cover (tenant_id, test_id, result, excluded, system_id)` lets those counts run from the index. Benefits the once-per-restart startup recalc and the per-tenant TASK F recalcs introduced in 0.5.3.

### Database
- **Schema v29 → v30** — adds `idx_systems_prune` and `idx_results_recalc_cover`. Pure index additions, no data change, fully idempotent (`CREATE INDEX IF NOT EXISTS`). Fresh installs get both in `initialize_database`.

---

## [0.5.3] - 2026-06-02

**Performance pass on auto-group reconciliation + compliance recalc.** No behavioural change — identical group memberships and compliance numbers — but the heartbeat hot path and the post-rule-save sweep get materially cheaper, and a membership change no longer triggers a full-fleet compliance recompute on multi-tenant deployments. Full rationale in `docs/design/0.5.3-auto-groups-perf.md`.

### Changed
- **Heartbeat reconciliation short-circuits when the tenant has no auto-rules (P1).** `apply_auto_groups` previously loaded the full system snapshot — including a scan of the `containers` table — before checking whether any rules existed. Installs that don't use auto-groups paid that cost on every heartbeat. Now a single indexed `EXISTS` on `systems_in_groups` (auto-managed only) decides whether there's stale membership to clean up; if there are no rules and no auto memberships (the common case), the function returns before touching the snapshot. Correctness preserved: it only skips when *both* are empty, so a rule disabled out-of-band still gets its stale memberships cleaned.

- **Heartbeat reconciliation short-circuits when nothing rule-relevant changed (P3).** New `systems.auto_group_fp` column stores a SHA-256 of the rule-relevant fields (hostname, ip, os, arch, ver, status, mem_total_mb, disk_total_gb, containers_exists, runtimes, container_images) at last evaluation — folded into the existing snapshot SELECT, so no extra read. When the freshly-computed fingerprint matches the stored one, rule evaluation, the membership query, and all writes are skipped. `uptime_secs` is deliberately excluded from the fingerprint (it changes every heartbeat and would defeat the skip); a rule on uptime reconciles on the once-per-tick cadence instead. The fingerprint is re-stamped whenever it drifts.

- **Full-tenant sweep parses rules once instead of per-system (P2).** `apply_auto_groups_for_tenant` (run on rule create / edit / toggle) previously re-loaded and re-compiled every rule's regex once per system — O(N×R) regex compilation on the synchronous path an admin waits on. It now parses the rule set once and reuses it across all systems via the new `apply_auto_groups_with_rules`. The sweep also nulls every fingerprint in the tenant up front and forces re-evaluation (bypassing the P3 skip, since *rules* changed rather than *fields*) — this restores the pre-P3 self-healing guarantee: a system the sweep errors on keeps a NULL fingerprint and is re-evaluated on its next heartbeat.

- **Compliance recalc is scoped to dirty tenants instead of the whole fleet (Scope #4).** `recalculate_current_compliance` previously recomputed every test / system / policy across *all* tenants whenever any membership changed. On a multi-tenant deployment a single new system joining a group in one tenant forced a recompute of every other tenant. The four aggregation passes now take an optional tenant filter; the scheduler's auto-group dirty-bit consumer (TASK F) collects the DISTINCT dirty `tenant_id`s and recomputes only those via the new `recalculate_current_compliance_for_tenant`. The global path is unchanged for startup and the manual `sync_tx` edit path. Tenant isolation is a hard schema boundary (every aggregation JOIN is tenant-local), so scoped numbers are identical to the global pass for that tenant.

- **3 new unit tests** (26 total) pin the fingerprint contract: stable for identical fields and independent of the stored value, flips for every fingerprinted field (guards against forgetting to extend the fingerprint when a new rule field is added), and ignores `uptime_secs`.

### Database
- **Schema v28 → v29** — adds `systems.auto_group_fp TEXT` (nullable). NULL default means every system is treated as "changed" on its first post-upgrade heartbeat, reconciled exactly once, and fingerprinted from then on. Idempotent `column_exists` guard; fresh installs get the column directly in `initialize_database`.

---

## [0.5.2] - 2026-06-02

**Headline: Automatic group assignment.** Define a rule once ("`os_family equals linux`", "`containers_exists is true`", "`hostname regex web-prod-`"), and every new and existing system that matches lands in the right groups on its next heartbeat — and out of them again when its metadata stops matching. Policies attached to those groups pick up the new members automatically through the existing scope chain. No more "I provisioned a Linux box yesterday, why isn't it in CIS-Linux yet."

### Changed
- **Policy editor's group picker visually marks auto-managed groups.** The group duallistbox on `/policies/add` and `/policies/edit/{id}` already included auto groups (no `auto_managed` filter), but they rendered as plain names — admins couldn't tell at a glance which entries would update automatically vs which they had to maintain. Each auto-group entry now appears as `✨ <name> (auto)` with `data-auto="1"` on the `<option>`. Order: manual groups first (alphabetical), then auto groups (alphabetical). A help line below the picker spells out that auto and manual groups can be mixed freely in a single policy — useful for "linux fleet (auto) + special-handling list (manual)" combinations.

### Fixed
- **`derive_os_family` now recognises `"Mac OS …"` (with a space) as macOS.** User report: an auto-group with rule `os_family contains "mac"` failed to match a Mac whose agent reported `os = "Mac OS 26.5.0"` (the literal display string `os_info 3.x` emits on Apple Silicon). The matcher's macOS branch only checked for `"darwin"` and `"macos"` (no space), so the lowercased input `"mac os 26.5.0"` fell through to the catch-all `"other"`. Once `os_family` was `None`, `match_opt_string(None, …)` short-circuited to `false` and the system never joined the group. Broadened the macOS branch to also match `"mac os"` (with space) and the `mac…` prefix — covers `"Mac OS"`, `"Mac OS X"`, `"macOS"`, `"Darwin"`, and `"Macintosh"`, all verified by a new regression test (`derive_os_family_macos_variants`). Linux / Windows / BSD strings stay on their own branches (no false positives). 23/23 tests pass.

### Changed
- **Auto-group substring operators (`contains` / `not_contains` / `starts_with` / `ends_with`) are now case-insensitive.** Matches the universal admin-UI expectation — `os contains "Mac"` matches a system whose agent reports `"Mac OS 14.5"`, and `os_family contains "Linux"` matches the normalised lowercase `"linux"`. Side-steps the case mismatch between the `os_family` normalization (always lowercase) and the natural admin capitalisation. `equals` / `not_equals` remain case-sensitive — explicit-match semantics — and `regex` is unchanged (case-sensitive by default; admins can write `(?i)` to opt out). One new unit test (`string_substring_ops_are_case_insensitive`) locks in the behaviour. 22/22 tests pass.

  **Migration impact:** zero behavioural change for rules that were already matching. Rules that were *failing to match* due to case mismatch (e.g. an admin who wrote `os contains "Mac"` and saw their Mac systems sit outside the group) now match on the next heartbeat — or immediately if the admin re-saves the rule, which runs the full-tenant sweep.

- **Enum-typed auto-group fields now accept `contains` / `not_contains`.** `os_family`, `arch`, `status`, and `has_runtime` previously only allowed exact-match operators (`equals` / `not_equals` / `in` / `not_in`); they now also accept substring matching. Useful for rules like `os_family contains "bsd"` (matches both `freebsd` and `openbsd` without enumerating each), `status contains "pend"`, or `has_runtime contains "dock"` (matches both `docker` and a hypothetical `docker-ce`). The eval path was already substring-aware via `match_string` — only `Field::accepts()` (server) and the JS operator catalog (UI) needed loosening. One new unit test (`enum_fields_accept_contains`) locks in the new validator + eval behaviour. 21/21 tests pass.

- **Auto-group rule editor is now fully click-driven (matches the test-builder pattern).** The JSON textarea is gone — admins build rules with three dropdowns + one value input per row, "Add Condition" / trash-can buttons, up to 8 condition rows. No JSON syntax to learn, no curly braces to escape.
  - **Field dropdown** is grouped by category (Identity / Platform / Telemetry / Containers) with a friendly label per field. The picker mirrors the `Field` enum in `auto_groups.rs` exactly.
  - **Operator dropdown** is field-aware: picking a field instantly repopulates the operator list with only the operators that field's type accepts. Mirrors `Field::accepts()` in the evaluator — the two are explicitly documented as paired.
  - **Value input** carries a per-field placeholder hint (e.g. `10.0.0.5  or for in_cidr: 10.0.0.0/24` for the IP field, `docker | podman` for `has_runtime`, `true  or  false` for booleans). Admins see expected shape before typing.
  - **Server-side coercion** of the typed value happens in the new `build_conditions_json_from_form` helper: `in` / `not_in` strings split on commas → JSON array; numeric ops on numeric fields parse as number; `containers_exists` parses truthy strings (`true`/`1`/`yes`/`on`) as `true`. The resulting JSON goes straight through the existing `validate_conditions_json` — one validator, two front-ends.
  - **Edit form pre-fills** every row from the stored JSON via `explode_conditions_for_form`: arrays flatten to comma-joined strings, numbers / bools stringify, strings pass through. Round-tripping a rule through save → reload → save is a no-op.
  - **10 new unit tests** in `auto_groups::tests` cover the form helpers: numeric / bool coercion, comma-split, blank-row dropping, partial-row rejection, empty-rule rejection, and explode round-trip for all three value shapes (string, number, array).

### Added
- **Scheduler consumes `systems.compliance_dirty`.** New TASK F in the 60-second scheduler loop: if any system has `compliance_dirty = 1`, clear the flag and run `recalculate_current_compliance`. This is what makes the heartbeat-time auto-group reconciliation actually reflect in compliance scores — without it, a system that moved into a new auto group (and therefore picked up new policies via the group → policy → tests chain) would carry stale `compliance_score` / `tests_passed` / `tests_failed` until the next admin action or restart. The COUNT pre-check keeps the no-dirt-flags steady state cheap (one indexed scan against the partial index `idx_systems_compliance_dirty`). Clear-before-recalc ordering means concurrent heartbeats setting NEW flags during the recalc window survive to the next tick — bounded one-tick (60s) lag matches the "accept the lag" decision from the design doc.

### Changed
- **Manual group pickers filter out auto-managed groups.** Three places where an admin would otherwise be able to pick an auto group, only to have the choice undone on the next heartbeat:
  - **Systems list — "Add to Group" bulk modal**: the dropdown now only lists `auto_managed = 0` groups. If no manual groups exist the modal shows the existing "Create a group first" prompt.
  - **Per-system edit page — "Groups" multi-select**: same filter. Auto memberships still display on the systems list / detail (read-only) — they're just not editable from here. Admins manage them via the rule editor.
  - **Per-system edit save**: the DELETE-then-INSERT cycle now only clears manual memberships before re-inserting. Auto memberships survive the save untouched. Without this, saving the edit form would wipe rule-driven memberships and the next heartbeat would re-add them — visible churn and audit-log noise for zero benefit.
  - **Bulk `/systems/bulk/add_group` POST validator**: extended to require `auto_managed = 0` on the target group. Defence in depth against a replayed / hand-crafted POST.

### Added
- **Admin UI for auto-groups — `/system_groups/auto/{add,edit,toggle}`.** Admins create and manage auto-managed groups from the unified System Groups page.
  - **New Auto Group** button (Admin-gated, alongside the existing Editor-gated **New Group**). Both buttons live in the same card header so admins don't need to hunt for a separate menu.
  - **Type badge** column on the groups list. Manual groups get a grey `Manual` badge; auto groups get a blue `Auto` badge with a magic-wand icon.
  - **Edit routes by type.** Clicking Edit on a manual group goes to the existing membership editor; clicking Edit on an auto group goes to the rule editor. The legacy `/system_groups/edit/{id}` handler also auto-redirects to the rule editor if it's invoked against an auto group (defence in depth — any stale link still lands in the right place).
  - **Rule editor** is a focused JSON-textarea form with live client-side parse validation, plus authoritative server-side validation on save (regex compiles, CIDR parses, operator is valid for the field's type, rule is non-empty). Field / operator / example reference panel renders alongside so admins don't need to flip back to the design doc. A "Currently matching" preview shows which systems are in the group right now.
  - **Enable / disable toggle** as a one-click button — disabling drops every matching system out of the group (the rule evaluates to "no system matches" while disabled) but preserves the rule definition for later re-enable. The toggle runs the full-tenant sweep so the effect is immediate.
  - **Save triggers a full-tenant sweep** — `apply_auto_groups_for_tenant` runs against every system right after the rule is committed, so existing systems land in (or out of) the new auto group on the next page load. Acceptable in v1 per the design doc's resolved Q3.

- **Audit events for auto-group lifecycle.** Every state-changing admin action on auto-groups now lands a row in `audit_log`: `auto_group_create`, `auto_group_update`, `auto_group_enable`, `auto_group_disable`, `auto_group_delete`. The matching `group_delete` event for manual groups was added in passing — both share the existing delete path, distinguished by `target_type` (`group` vs `auto_group`). Details column carries name + `systems_reassigned=N` so auditors can see how much each change moved.

- **Heartbeat hook calls `apply_auto_groups` on every successful agent check-in** (`client.rs` `/send` handler, right after `ingest_containers`). The reconciler is best-effort: any error is logged at `warn` and the heartbeat continues — the user-visible systems UPDATE + container ingest are never rolled back over a rule-eval glitch. The next heartbeat retries the eval. In the steady-state (no rules, or no membership changes) the call is one tiny indexed SELECT against `auto_group_rules` plus one against `systems_in_groups`, both empty/small — negligible. Membership churn flips `systems.compliance_dirty = 1` so the existing scheduler picks up the recalc on its next tick; no synchronous compliance work on the hot path.

- **Auto-group rule evaluator (`scmserver::auto_groups`).** New module that the heartbeat hook and rule editor call into.
  - `Field` / `Operator` enums cover the parameter catalog from the design doc (hostname, ip, os, os_family, arch, platform, ver, status, mem_total_mb, disk_total_gb, uptime_secs, containers_exists, has_runtime, any_container_image — plus the obvious operators per type). `Field::accepts(op)` rejects nonsense pairings like `mem_total_mb contains "x"` at validation time, so admins can't save unevaluatable rules.
  - `SystemSnapshot` is loaded fresh from `systems` + `containers` on every call (cheap — one SELECT per side). `os_family` and `platform` are derived in-Rust from the raw `os` string, so the schema doesn't gain extra denormalised columns. Container fields (`containers_exists`, `runtimes`, `container_images`) are built from the per-host `containers` rows already collected for 0.5.0.
  - `parse_conditions(json)` parses and structurally validates a rule (regex compiles, CIDR parses, `in` arrays non-empty); `validate_conditions_json` is the stricter wrapper used on POST (additionally rejects an empty rule, which would silently match everything).
  - `apply_auto_groups(tx, tenant_id, system_id)` is the reconciler. Loads the system's snapshot + the tenant's enabled rules, evaluates each rule (conjunctive: all conditions must match), diffs the resulting target group set against the system's current auto-group membership (joining on `system_groups.auto_managed = 1` so manual groups are completely untouched), applies the INSERTs / DELETEs, and — if anything changed — sets `systems.compliance_dirty = 1` so the existing scheduler picks up the recalc on its next tick. Returns a bool indicating "did anything change" for the heartbeat caller's audit decision.
  - `apply_auto_groups_for_tenant(pool, tenant_id)` is the full-sweep version used by the rule editor on save / disable. One transaction per system so a single failure doesn't roll the whole sweep back.
  - 10 unit tests cover string ops + regex, IP/CIDR match, numeric + semver compare, boolean + multi-value-runtime, enum `in`, NULL-field semantics, and validator rejections for empty rules / wrong op-for-field / bad regex / bad CIDR. All passing.
  - New deps: `regex 1.10`, `ipnet 2.9`.

- **Schema v27 → v28 — automatic group assignment groundwork.** Three additions that the upcoming auto-groups feature builds on, all back-compat with existing data:
  - `system_groups.auto_managed` (INTEGER, default 0) — group type flag. `0` = manual (admin-curated, existing behaviour). `1` = auto (membership reconciled by a rule). Immutable after group creation. All existing groups remain manual.
  - `systems.compliance_dirty` (INTEGER, default 0) — set to `1` when a system's auto-group membership changed on heartbeat and its current compliance needs a recalc on the next scheduler tick. Consumed and cleared by `recalculate_current_compliance`. Lets the heartbeat hot path stay fast while still keeping compliance fresh within one scheduler interval. Indexed on `(tenant_id, compliance_dirty) WHERE compliance_dirty = 1` so the scheduler sweep is O(dirty), not O(all systems).
  - `auto_group_rules` table — one rule per auto group via `UNIQUE(group_id)`. Holds `name`, `description`, `conditions` (JSON array of `{field, op, value}` AND-evaluated), and `enabled` flag. FK to `system_groups` with `ON DELETE CASCADE` so deleting an auto group cleanly removes its rule. Indexed on `(tenant_id, enabled)` for the heartbeat fast-path lookup.

  No behavioural change yet — only the column/table groundwork. Membership eval, heartbeat hook, and admin UI land in subsequent steps.

---

## [0.5.1] - 2026-05-31

### Fixed
- **Container chevron missing for some hosts in the Systems list.** Two related bugs surfaced on tenants whose container-having hosts spanned multiple DataTables pages:
  - Rows on non-current pages never got the `▶` chevron — the previous paint was a one-shot `$.each(...)` at init time, but DataTables detaches non-current-page rows from the DOM, so the iterator only ever saw page 1. Paginating to other pages attached the rows but left the `expand-toggle` cells empty.
  - Even rows on the *current* page sometimes had empty cells — `responsive: true` performs an async redraw after init that wipes any pre-paint DOM mutations.
  - Both fixed by hooking into DataTables' `rowCallback`, which fires for every row at every redraw (initial render, pagination, sort, search, responsive resize). The chevron now survives every lifecycle event. `containersBySystem` is initialised above the `DataTable()` init so the callback can reference it; the dedicated `$.each` paint loop is removed as redundant.

---

## [0.5.0] - 2026-05-31

### Fixed
- **Schema v26→v27 catch-up migration.** Deployments that ran the early in-place edits of the v26 block during 0.5.0 development ended up at v26 with an outdated shape — missing the post-IMAGE/NETWORK container elements (`CONTAINER`, `PRIVILEGED`, `RUN_USER`, `MOUNT`, `EXPOSED_PORT`, `READ_ONLY_FS`, `HEALTH_CHECK`) and / or with the old 3-column `results` primary key. Symptoms: missing entries in the test-builder Element dropdown; `error returned from database: (code: 1) ON CONFLICT clause does not match any PRIMARY KEY or UNIQUE constraint` on every result POST. New v27 migration is idempotent: re-seeds elements via `INSERT OR IGNORE`, then introspects `sqlite_master` to see whether the `results` PK already includes `container_id` and only rebuilds the table when it doesn't. Fresh installs that landed cleanly at v26 traverse v27 as a no-op.

### Added
- **Canned container policy — applicability gate via `CONTAINER EXISTS`** (`cis-container-config-l1` → **1.1.1**). All 11 tests in the starter policy now declare `CONTAINER EXISTS` as their applicability — on a host without Docker / Podman the tests short-circuit to NA via the standard applicability path, making "not applicable here" explicit in the policy JSON rather than an implicit fallback. Same end-user result as before; cleaner audit trail. Doubles as a worked example of the `CONTAINER` element being used the way it's intended (as an applicability gate, not as a standalone test).

- **Test-builder UI — Container elements grouped under their own `<optgroup>`.** The Element `<select>` in both the Add Test and Edit Test forms (and in their applicability-condition selects) now renders two visual groups — **Host** (AGENT / OS / CMD / FILE / SERVICE / …) and **Container** (CONTAINER / IMAGE / NETWORK / PRIVILEGED / RUN_USER / MOUNT / EXPOSED_PORT / READ_ONLY_FS / HEALTH_CHECK). Browser-native rendering, italic headers, indented options, search-as-you-type all work. Classification lives in one place (`scmserver/src/tests.rs::is_container_element`) so adding a future container element automatically lands in the right group.

- **Container test elements — 6 more agent-side elements** rounding out the design-doc set. Each is a single match arm in `scmclient::compliance::evaluate()` plus a seed-row in `elements` — uniform with every other element, no architectural change.
  - **`PRIVILEGED`** (`EXISTS` / `NOT EXISTS`) — checks `HostConfig.Privileged`. CIS Docker 5.4.
  - **`RUN_USER`** (`CONTENT`) — checks `Config.User` with the standard string conditions. CIS Docker 4.1 ("don't run as root").
  - **`MOUNT`** (`EXISTS` / `NOT EXISTS`, input = host path) — substring-matches against bind-mount `src` paths. CIS Docker 5.5 (block `/var/run/docker.sock` mount).
  - **`EXPOSED_PORT`** (`EXISTS` / `NOT EXISTS` / `COUNT`, input = `port/proto`) — checks `NetworkSettings.Ports`. EXISTS substring-matches one entry; COUNT applies a numeric condition to the total.
  - **`READ_ONLY_FS`** (`EXISTS` / `NOT EXISTS`) — checks `HostConfig.ReadonlyRootfs`. CIS Docker 5.12.
  - **`HEALTH_CHECK`** (`EXISTS` / `NOT EXISTS`) — checks `Config.Healthcheck` presence. Observability hygiene.

  All six route through `is_per_container_element` and yield one result per discovered container. Three small private helpers in `compliance.rs` (`bool_selement`, `container_mount_matches`, `container_exposed_ports`) handle the boolean-flag / JSON-parsing repetition. UI grouping in `tests.rs::is_container_element` extended so they land under the **Container** `<optgroup>` in the test-builder dropdown.

  Canned policy **`cis-container-config-l1`** bumped to **1.1.0**: 5 tests → 11 tests, exercising every new element with a real-world example (privileged check, run-as-root, Docker-socket mount, SSH port exposure, read-only FS enforcement, HEALTHCHECK presence).

- **Container test elements — `IMAGE`, `NETWORK`, `CONTAINER` (steps 6+7/8).** Three new compliance elements, all evaluated **agent-side** through the same dispatch path as every other element in OpenSCM (FILE, CMD, PROCESS, SERVICE, …). Uniform architecture: no separate server-side evaluator, no parallel dispatch path, no `evaluator` routing column. Applicability works for every element the same way.
  - **`IMAGE`** (per-container) — checks against the container's image reference. Sub-elements: `NAME`, `TAG`, `DIGEST`, `SOURCE` (registry host, parsed from the reference using standard Docker rules — `docker.io` for implicit, namespace-aware first-path-component detection).
  - **`NETWORK`** (per-container) — `MODE` sub-element checks `host`/`bridge`/`none`/`container:<id>`/named network.
  - **`CONTAINER`** (per-host) — `EXISTS` PASSes when `docker` OR `podman` is on `$PATH`; `NOT EXISTS` is the inverse. Great for use in `applicability` of host-level tests (CMD, FILE, …) to gate them to container hosts only.
  - **Per-container result identity**: when the agent evaluates a test whose conditions use IMAGE or NETWORK, it enumerates its discovered container inventory and produces **one result per container**, identified by the container's `runtime_id`. The server resolves `runtime_id` → `containers.id` via `(host_system_id, runtime_id)` and binds it on the result row. Tests with no container conditions still produce one host-level result with `container_id=0`. Hosts with zero containers produce a single NA at host scope.
  - **`ComplianceResult` payload gains `container_runtime_id: Option<String>`** — old agents that omit it continue to work (server treats as host result).
  - **Canned starter policy** `cis-container-config-l1.json` lands in the OpenSCM-store under category "Containers": 5 tests exercising IMAGE + NETWORK (tag pinning, explicit registry source, host-network isolation, network-mode sanity, test/dev image-name drift).
  - **Schema (v26)**: `results` primary key widened to `(tenant_id, system_id, test_id, container_id)` so per-container results coexist with host results. `container_id NOT NULL DEFAULT 0` — host rows bind 0, per-container rows bind the resolved id. Both UPSERTs (heartbeat result-write in `client.rs`, all paths) updated to target the full 4-column key.

  The other 6 metadata-only elements from the design doc (`PRIVILEGED`, `RUN_USER`, `MOUNT`, `EXPOSED_PORT`, `READ_ONLY_FS`, `HEALTH_CHECK`) ship alongside — see the entry just above.

- **Container support — Systems-list inventory + detail modal (step 5/8).** The first user-visible payoff of the container work:
  - **Expand chevron** — every system row gains a left-side `▶` cell when the host has any containers; click to reveal a DataTables child row containing a nested table of that host's containers (runtime icon, name, image, IP, status).
  - **Detail modal** — clicking any container row opens a modal showing the full inventory metadata: runtime, image + digest, IP, run-user, network mode, privileged / read-only / health-check flags, restart policy, exposed ports, mount list, added capabilities, first/last seen timestamps. Mounts and ports render from the JSON cached at ingest — no extra round-trip.
  - **Server-side**, the `systems` handler fetches every visible host's containers in one bulk query (`WHERE host_system_id IN (...)`), groups by host id, and embeds the result as a single JSON `<script id="containers-by-system" type="application/json">` blob the client-side JS reads on chevron click. Zero per-row round-trips when expanding.
  - DataTables `columnDefs` updated for the new column shift; new sort uses column 4 (Name) instead of column 3 (which became Name + 1 after the chevron column landed).

  Hosts with no containers show no chevron; reverted/non-Linux hosts are unaffected. This closes the inventory loop end-to-end: agent discovers → server stores → UI shows it.

- **Container support — daily retention prune (step 4/8).** The scheduler's existing once-per-UTC-day prune tick gains a fourth helper (`prune_containers`) alongside the audit / report / notification prunes. Per-tenant `container_retention_days` setting (seeded at 7 days in step 1; configurable via `Admin → Settings → General`, validated as `0` (forever) or 1-10000 days) drives a `DELETE FROM containers WHERE last_seen < now - N days` per tenant. A successful trim writes a `retention.containers_pruned` audit row with the count + retention window so the cleanup is itself auditable. This is the second half of the staleness story — the heartbeat ingest already removes containers the agent stopped reporting (stragglers); this prune handles containers whose *host* stopped checking in entirely.

- **Container support — server ingest (step 3/8).** Heartbeat handler now persists the `containers` array shipped by Linux agents into the `containers` table that landed in step 1. Three explicit cases per design doc §3 "Lifecycle":
  - `containers` field **absent** (old agent or non-Linux) → leave existing rows alone; they age out via retention (step 4).
  - `containers: []` → agent explicitly reports no containers; delete every container row for this host so the UI matches reality immediately.
  - `containers: [...]` → upsert each entry keyed on `(host_system_id, runtime, name)`, preserving `first_seen`; delete any row for this host whose `(runtime, name)` is no longer in the report (stragglers from a previous tick).

  Implemented as a private `ingest_containers` helper running inside the existing heartbeat transaction, so a transient DB error rolls back the systems UPDATE too — the agent retries the whole payload on the next tick. Stable scan-boundary timestamp (`now_str` captured once in Rust) keeps the upsert + straggler-delete monotonic. `INSERT ... ON CONFLICT DO UPDATE` preserves `first_seen` while refreshing everything else, so the "container has been running since X" date in the upcoming detail view is accurate across heartbeats.

  Containers now flow end-to-end: agent discovers → server stores. Inventory UI (step 5) and container-only test evaluators (step 6) are next.

- **Container support — agent discovery (step 2/8).** The Linux agent now detects locally-installed Docker / Podman runtimes and enumerates their containers on every heartbeat. For each container, it captures the runtime ID, name, image (with digest), status, IP, plus the metadata that will drive future container-only tests: privileged flag, run-as user, network mode, exposed ports, mounts, added capabilities, read-only-fs flag, restart policy, and presence of a `HEALTHCHECK`. Metadata is collected via one `<runtime> inspect` shell-out per container, parsed from the existing in-memory JSON. The new `containers` field on the heartbeat payload is omitted entirely (Option::None) when no runtime is installed, so old servers see no new field at all — schema groundwork from step 1 keeps existing servers receiving these heartbeats without complaint. Soft-fails on missing permission (rootless / no docker group). Non-Linux platforms return an empty list with zero shell-outs; LXC / LXD are intentionally not enumerated — install the agent inside the OS container per the design doc.

- **Container support — schema groundwork (step 1/8).** Lays the database foundation for the upcoming container inventory and container-only tests; nothing reads or writes these yet, but a fresh install and any existing tenant on schema v25 will land at v26 with the new shape in place. Specifically:
  - New `containers` table — per-host inventory keyed by `(host_system_id, runtime, name)`. Stores runtime identifier (docker / podman / kubernetes), image + digest, status, IP, plus cached metadata fields (privileged, run_user, network_mode, exposed_ports as JSON, mounts as JSON, capabilities, read-only-fs, restart_policy, health_check) for future container-only element evaluation. `first_seen` / `last_seen` drive retention.
  - New `results.container_id` column and widened primary key `(tenant_id, system_id, test_id, container_id)` so per-container results can coexist with host results. `container_id` is `NOT NULL DEFAULT 0` — host rows bind 0 (existing semantics preserved); per-container rows bind the real container id.
  - Seed the first two container-only **elements** in the lookup table: `IMAGE` and `NETWORK`. Other container elements from the design doc (`PRIVILEGED`, `RUN_USER`, `MOUNT`, `EXPOSED_PORT`, `READ_ONLY_FS`, `HEALTH_CHECK`) are deferred to a later 0.5.x increment.
  - Seed five new **sub-elements**: `NAME`, `TAG`, `DIGEST`, `SOURCE` (for IMAGE — the source registry host), and `MODE` (for NETWORK). Avoided `REGISTRY` to prevent a name clash with the existing Windows-Registry `REGISTRY` element.
  - New per-tenant setting `container_retention_days` (default `7`, `0` = forever) — will drive a future daily-prune of stale container rows alongside the existing audit/report/notification prunes.
  - Schema migration v25 → v26 with `column_exists` guard for the `results.container_id` ALTER; fresh-install path mirrors the same table creation and seed data.

  Reference: `docs/design/0.5.0-containers.md` section 3 (data model) and section 7 (container-only elements).

---

## [0.4.8] - 2026-05-26

### Changed
- **SQLite tuning + pool-wide pragma application.** Two things land together:
  1. **Bug fix:** PRAGMAs were applied via `pool.execute()` at startup, but SQLite pragmas are per-connection — only the first connection in the pool actually had them set. Every subsequent connection ran with sqlite's defaults (FULL synchronous, no busy_timeout, no foreign-key enforcement, etc.). Pragmas are now applied via a `SqlitePoolOptions::after_connect()` hook so every connection the pool hands out has the same tuning. Same fix applied to the SaaS binary.
  2. **Tuning:** added `temp_store=MEMORY` (keep transient B-trees in RAM during big dashboard aggregations), `mmap_size=268435456` (256 MiB kernel-page-cache-backed reads — much lower latency for hot pages), `cache_size=-65536` (64 MiB per-connection page cache, up from the 2 MiB default), and bumped `busy_timeout` from 5 s → 10 s. Existing settings (`journal_mode=WAL`, `synchronous=NORMAL`, `foreign_keys=ON`) preserved.

- **Compliance engine — eliminate the worst shell-out hot paths.** Three of the most-fired element backends are replaced with native code that avoids forking a child process per test. A policy with dozens of PACKAGE / SERVICE / Windows-registry tests now scans noticeably faster, and the OS process table stays calm during a scan.
  - **Windows packages** (PACKAGE `EXISTS` / `VERSION`) — replaced `powershell -Command "Get-Package ..."` with a native walk of the two Uninstall registry hives (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` plus the `WOW6432Node` variant) via the existing `winreg` crate. Per-call cost drops from roughly 1-2 s (PowerShell cold start dominates) to under 10 ms. ~150× speedup.
  - **Debian/Ubuntu packages** — replaced the `dpkg-query` fork-per-call with a native parser of `/var/lib/dpkg/status`. The parsed map is cached in a `Mutex<Option<(mtime, HashMap)>>` and only re-parsed when the file's mtime changes. First call ~10× faster than `dpkg-query`; every subsequent PACKAGE test in the same scan run is effectively free (HashMap lookup).
  - **systemd services** (SERVICE `ACTIVE` / `INACTIVE` / `ENABLED` / `DISABLED`) — collapsed the two `systemctl is-active` + `systemctl is-enabled` shell-outs into a single `systemctl show -p ActiveState -p UnitFileState`, cached for 300 ms so a test that checks both states on the same unit costs one fork rather than two.

  No behavioural change — the boolean outcomes are unchanged. Deferred to a future patch: native RPM database parsing (DB format varies by distro version), full D-Bus replacement of systemctl (needs the `zbus` dep), and native macOS receipts/plist read for `pkgutil`.

### Fixed
- **`scmclient run` defaulted CMD/PowerShell off, generating noise warnings** — the local-policy runner inherited the managed-agent gating logic where `cmd_enabled` / `ps_enabled` must be opted into per-agent to prevent a server from pushing arbitrary commands. In local-run mode that threat model doesn't apply (the user supplied the policy file by hand at the CLI), so the gates are now **on by default**. The `--cmd-enabled` / `--ps-enabled` flags are kept for symmetry but redundant; new `--no-cmd` / `--no-ps` flags let you explicitly opt out (e.g. for a sandbox / CI scan that must not exec shell). Eliminates the wall of `CMD element is disabled` warnings when running a CIS Linux policy locally.

---

## [0.4.7] - 2026-05-26

### Added
- **LDAP directory support** — admins can now delegate user authentication to an external LDAP server (OpenLDAP, Active Directory, FreeIPA, 389-DS, etc.) instead of storing every password in the OpenSCM database. New **Directories** section under `Admin → Settings` (sidebar link gated on Admin role) provides full CRUD over LDAP integrations:
  - **Per-tenant directories** stored in a new `directories` table (schema migration v24→v25); each entry holds host, port, TLS settings, base DN, service-account bind credentials, and the user-lookup attribute (`uid`, `sAMAccountName`, etc.).
  - **Test Connection** button on both the list page (one click per directory) and inside the edit form — `POST /admin/directories/test/{id}` runs a service-account bind and returns `{ok: bool, error: "…"}` JSON; LDAP errors are surfaced verbatim so a misconfigured base DN or wrong password produces an actionable message.
  - **Skip TLS verification** toggle for self-signed certs in dev/test environments, with a prominent in-form security warning. Production deployments should leave it off.
  - **User Add form** gains an "Authentication Source" dropdown when at least one directory exists — choosing a directory hides the password field and replaces it with an "External Username" input (defaults to the local Login Username if blank). New columns `users.directory_id` and `users.external_username` track the mapping.
  - **Login flow** in `auth.rs` checks `directory_id`: NULL → existing bcrypt path; set → look up the directory, bind as service account, search by user attribute, then re-bind as the resolved DN with the submitted password. Bcrypt is still run against a dummy hash for LDAP users to keep timing parity.
  - **Audit log** events: `directory.create`, `directory.update`, `directory.delete`, `directory.test_success`, `directory.test_failure`.
  - **Refuses to delete** a directory while any user still references it (with a count in the error message), so an admin can't accidentally lock out a fleet of LDAP users.

  Out of scope for v1: auto-provisioning (admins still create user rows manually with role + display name), group → role sync, OIDC/SAML federation (those are tracked separately as #3 SSO), Kerberos/GSSAPI bind, field-level encryption of the bind password (stored plaintext in DB — protect the DB file accordingly; documented warning in the edit form).

  **CE/EE only — disabled in SaaS mode.** LDAP requires the OpenSCM server to make outbound connections to the customer's internal LDAP server, which doesn't fit the SaaS network topology (customers shouldn't expose their LDAP to the public internet, and per-customer VPN tunnels are operationally untenable). In SaaS mode, the **Directories** sidebar entry is hidden, every `/admin/directories/*` route returns a redirect to the dashboard with an "LDAP not available in SaaS mode" message, and the "Authentication Source" dropdown is absent from the user-add form. The right SaaS identity story is browser-mediated federation (OIDC/SAML) — tracked separately as #3 SSO.

  Built on the `ldap3` crate (sync API via `tokio::task::spawn_blocking`, rustls TLS backend).

---

## [0.4.6] - 2026-05-25

### Added
- **Local policy run (CLI subcommand)** — `scmclient run --policy <file.json>` evaluates a standard OpenSCM policy file against the local host with **no server interaction at all**. Same compliance engine, same JSON format used by the policy store — bypasses only the network/heartbeat layer. Opens up several use cases the managed-agent model can't reach:
  - **Air-gapped systems** — get CIS/STIG scoring without deploying the server side
  - **CI/CD pipelines** — `scmclient run --policy cis-debian-13.json --format json --strict` returns a non-zero exit code on any FAIL; pair with `jq` to extract findings
  - **Policy authoring** — test a custom policy locally before publishing
  - **One-off audits** — consultants doing a spot-check without long-term enrollment
  - **Customer-shipped hardening kits** — vendors bundle agent + policy as a portable scanner

  Output formats: `text` (human-readable; default) and `json` (machine-readable). Flags: `--strict` (exit 1 if any test fails), `--failed-only` (text mode skips PASS/NA), `--cmd-enabled` / `--ps-enabled` (override default-off gates since the user is running an arbitrary policy file). Exit codes: 0 success, 1 strict mode + failures, 2 invalid args or unreadable/malformed policy file. No persistent state is touched — the runner never reads or writes the agent's identity, config beyond defaults, or any spool directory.

- **`SERVICE` compliance element** — first-class cross-platform service-state checks for the kind of controls auditors actually care about ("ensure auditd is enabled and active"). Four sub-elements, all boolean — no condition/sinput needed; input = service name:
  - `ACTIVE` — service is currently running
  - `INACTIVE` — service is currently stopped
  - `ENABLED` — service is configured to start at boot
  - `DISABLED` — service is not configured to start at boot

  Platform matrix:
  - **Linux** — `systemctl is-active` / `systemctl is-enabled`
  - **macOS** — `launchctl print system/<name>` / `launchctl print-disabled system`
  - **Windows** — `sc query <name>` / `sc qc <name>` (checks for `RUNNING` / `AUTO_START`)
  - **FreeBSD** — `service <name> status` / `sysrc -n <name>_enable`

  Returns `NA` when the platform's service manager isn't reachable (rare — only on stripped-down systems without an init system in `$PATH`). Not gated by `cmd_enabled` because the inputs are well-bounded service names, not arbitrary shell strings.

- **`PROCESS` element extensions** — two new sub-elements added to the existing PROCESS element (which previously only had `EXISTS` / `NOT EXISTS`):
  - `OWNER` — emits the username of the first matching process; applies the standard string conditions (`equals`, `contains`, etc.). Useful for "nginx must run as `www-data`, not root" checks. Returns `FAIL` if the process isn't running at all (can't check owner of a process that doesn't exist).
  - `COUNT` — emits the integer count of matching processes; works with numeric conditions (`more than 0`, `equals 1` for singleton daemons, etc.).

  Schema migration v23→v24 adds the `SERVICE` element row and the `COUNT` / `ACTIVE` / `INACTIVE` / `ENABLED` / `DISABLED` selement rows. `OWNER` was already present.

---

## [0.4.5] - 2026-05-25

### Fixed
- **Systems list sort order** — pending systems now show at the top of the list (so newly-enrolled agents awaiting approval are immediately visible), with the rest sorted alphabetically by name. Previously both the server-side SQL and the DataTables client-side sort ordered by ID ascending, which buried new systems at the bottom of the list once a tenant accumulated a few dozen agents. Both layers are now aligned: SQL uses `ORDER BY (pending first), s.name ASC`, and DataTables uses `[[0, "desc"], [3, "asc"]]` (hidden status column descending — `pending` sorts after `active` alphabetically — then Name ascending).

### Added
- **Retention policies for reports and notifications** — closes the long-running #9 by extending the existing daily prune that already handled the audit log. Two new per-tenant settings appear in `Admin → Settings → General`:
  - **Report Retention (days)** — applies to both `reports` (policy snapshots) and `system_reports`. Default `0` (keep forever) — audit work usually wants long history; admins who must trim for storage reasons can opt in.
  - **Notification Retention (days)** — applies to the bell-icon `notify` table. Default `30` — operational chatter piles up fast and is rarely useful after a month.

  Both accept `0` (forever) or 1-10000 days, validated server-side. The scheduler's daily-prune tick (previously only audit log) now also calls `prune_reports` and `prune_notifications` in the same pass, tracked by `last_daily_prune_day` to fire exactly once per UTC day. Successful trims are themselves audited as `retention.reports_pruned` and `retention.notifications_pruned` with `{"removed":N,"retention_days":D}` in the details field — so an auditor noticing data disappeared can answer "why" without grep. Schema migration v22→v23 seeds the two new settings rows on existing installs.

- **Live telemetry on heartbeat** — agents now send CPU usage, RAM, disk, and uptime with every heartbeat. The systems list shows a compact telemetry line under each system name: CPU %, RAM used/total (GB), disk used/total (GB), and uptime (days + hours). Old agents that don't send telemetry fields show nothing — the fields are all optional and `#[serde(default)]` on both sides. Schema migration v21→v22 adds six nullable columns to the `systems` table (`cpu_usage`, `mem_used_mb`, `mem_total_mb`, `disk_used_gb`, `disk_total_gb`, `uptime_secs`). Client uses the `sysinfo` crate (already a dependency) with a 500ms CPU sampling window for an accurate reading.

---

## [0.4.4] - 2026-05-25

### Added
- **Tenant signing key rotation** — admins can now rotate the Ed25519 keypair used to authenticate agent heartbeats without touching the database manually. A new **Rotate Key** button in `Admin → Settings → Danger Zone` shows the current key fingerprint and creation date, then presents a confirmation modal before generating a fresh keypair, deactivating the old one, and inserting the new active key. All registered agents automatically re-enrol on their next heartbeat — no manual action is needed per agent. The rotation is recorded as a `tenant.key_rotated` audit event with the new key fingerprint in the details field.

- **`exit_code` sub-element for `cmd`** — the `cmd` element now supports `exit_code` alongside `output`. Useful for commands that signal pass/fail via their return code rather than stdout (e.g. `equals 0` for success, `not equals 0` for failure). Works on both Unix (`sh -c`) and Windows (`cmd /C`).

- **`powershell` compliance element** — policy authors can now write Windows compliance tests using PowerShell commands instead of `cmd`. Two sub-elements are supported:
  - `output` — runs the script and applies the standard string conditions (`equals`, `contains`, `matches`, `starts_with`, etc.) against the combined stdout+stderr, identical to the `cmd` element.
  - `exit_code` — evaluates the integer exit code; `equals 0` is the standard "success" check.
  - On Windows the element tries `powershell.exe` (Windows PowerShell 5.x, always present) first, then falls back to `pwsh` (PowerShell Core 7+) if the former is not found.
  - On Linux/macOS the element always returns **NA** — use the `cmd` element with `sh` on those platforms.
  - Gated by `ps_enabled = true` in the `[client]` TOML config (Linux/macOS) or `PsEnabled = true` in the Windows registry key `HKLM\SOFTWARE\OpenSCM\Client`. Default is `false` for the same security reason as `cmd_enabled` — arbitrary script execution requires explicit opt-in.

---

## [0.4.3] - 2026-05-24

### Fixed
- **Upgrade button hidden for offline systems** — the per-row upgrade arrow and the "Upgrade All" toolbar button are now suppressed when a system is offline; previously both were visible even though queuing an upgrade to an unreachable agent has no effect.

### Added
- **System-report snapshot diff** — the same Compare flow now works on the System Reports tab. New `/reports/system/diff?a={id1}&b={id2}` (Viewer role) shows side-by-side per-policy result tables for a single system across two points in time, grouped by `(policy_name, policy_version)` so a version bump between scans surfaces as "old version removed / new version added" rather than silently masking a real change. Same colour-coding and aggregate counters as the policy diff. Same-system gating via a `data-system-key="<id>@<name>"` attribute on each checkbox in the System Reports list bulk toolbar, with server-side validation (system_id match, or system_name match as a fallback for systems that were deleted and re-created with the same hostname).

- **Report snapshot diff** — auditors can compare two saved policy-report snapshots side-by-side without downloading two PDFs and eyeballing them. New `/reports/diff?a={id1}&b={id2}` page (Viewer role) renders the union of every (system, test) pair across both snapshots in a colour-coded table:
  - **Green** — `improved` (was FAIL, now PASS)
  - **Red** — `regressed` (was PASS, now FAIL)
  - **Yellow** — `added` (test or system present only in the newer snapshot)
  - **Grey** — `removed` (test or system gone from the newer snapshot)
  - **Blue** — `changed` (other transitions — NA↔PASS, PASS↔NA, etc.)
  - **Untinted** — `unchanged`

  Aggregate counters at the top of the page summarise improved / regressed / added / removed / changed totals. Per-system card headers carry the same breakdown so an auditor can skim straight to the systems that moved. The handler refuses to compare snapshots of different policies (different name or version) and auto-orders by `submission_date` so "older" is always on the left regardless of which id the caller passed first.

  UI: the Policy Reports list bulk toolbar gains a **Compare** button that enables when exactly two checkboxes from the same policy are ticked; clicking navigates to `/reports/diff` with the two ids. Same-policy gating happens client-side via a `data-policy-key="<name>@<version>"` attribute on each checkbox, with the server still validating defensively.

  Out of scope for v1: three-way diff, system-report diff, PDF/email export of the diff itself (jump to either snapshot's PDF via the header links if you need one).

---

## [0.4.2] - 2026-05-22

### Added
- **`/health` and `/ready` probes** — two tiny HTTP endpoints that make OpenSCM deployable behind any modern load balancer or orchestrator without faking a request against `/login`. Both are public, unauthenticated, and whitelisted by the init_guard middleware so they answer even before `/install` completes — which means a k8s pod can come up cleanly during a fresh install or a rolling upgrade with mid-flight migrations.
  - `GET /health` → `200 OK` with `{"status":"ok"}`. No DB query, no work — pure liveness. Use for k8s `livenessProbe`, `HEALTHCHECK` in `scmserver/package/docker/Dockerfile`, basic LB pool membership.
  - `GET /ready` → `200 OK` with `{"status":"ok","schema_version":N}` only when the DB pool answers `SELECT 1` AND `schema_info` exists. Otherwise `503 Service Unavailable` with `{"status":"db_unavailable"}` (DB down) or `{"status":"setup_pending"}` (fresh install, /install not completed). Use for k8s `readinessProbe` so the LB keeps the old pod in rotation while a rolling deploy runs migrations on the new one.

- **Systems list — "Upgrade All" one-click action** — when at least one system in the tenant has a newer agent bundled in the server, an amber **Upgrade All** button appears next to the "Managed Systems" page title (Admin role only). Clicking it queues an UPGRADE row in the commands table for every eligible system in one POST. Eligibility uses the same semver-aware platform-match logic the per-row Upgrade button uses — systems on platforms the server doesn't ship binaries for are skipped silently. INSERT OR IGNORE means re-clicking the button on a fleet that's already mid-upgrade is idempotent (no duplicate queue rows). One `system.upgrade_queued_all` audit row records the eligible-vs-queued count and the full id list for traceability. Implementation: new `POST /systems/upgrade_all` handler, `has_upgradable: bool` computed server-side on `/systems` render so the button only appears when meaningful.

### Fixed
- **Systems list — per-row Upgrade icon wrapped to a second line** — the Actions column was 180px and the View button (the only text-bearing one in the row) took ~70px on its own, so when the Upgrade icon appeared the row pushed past the column width and the icon dropped to a new line. Widened Actions to 240px and added `white-space:nowrap` on the cell. Paid for the extra width by constraining three columns that were greedy: OS & Architecture → 160px, Agent → 70px, Last Seen → 120px. Name / IP / Groups keep their flex behaviour.

---

## [0.4.1] - 2026-05-22

### Added
- **Audit log — end-to-end** — admins can finally answer "who promoted that user / excluded that finding / approved that system / queued that upgrade" without grepping journalctl. The feature shipped as one coherent slice:

  - **Schema (DB migration v19 → v20)** — new `audit_log` table keyed by `(tenant_id, created_at DESC)` plus a partial index for fast newest-first scans. Default retention seeded at 730 days (≈ 2 years, covers most regulatory minimums); `0` = keep forever.

  - **Helper API** — `crate::audit::record()` for authenticated actions and `record_raw()` for pre-auth events (failed-login records the attempted username even when no AuthSession exists). Both are fire-and-forget — DB errors log via `tracing::error!` and never propagate, so an audit-side failure can't abort the operation being audited.

  - **First batch of call sites** (12 events):
    - `auth.rs` — `auth.login_success`, `auth.login_failure` (with `bad_password` or `unknown_user` details so brute-force patterns are visible), `auth.logout`
    - `policies.rs` — `policy.result_exclude`, `policy.result_unexclude`
    - `systems.rs` — `system.approve`, `system.delete`, `system.upgrade_queued`, `system.upgrade_queued_bulk` (single row per bulk action recording requested-vs-queued counts)
    - `users.rs` — `user.create`, `user.delete`, `user.edit_self`, `user.edit_by_admin` (distinct so auditors can filter role-change promotions vs profile edits)

  - **Client IP capture** — new `crate::handlers::ClientIp` extractor. Resolution order: `X-Forwarded-For` (leftmost entry — typical reverse-proxy header) → `X-Real-IP` (nginx's other forwarding header) → `ConnectInfo<SocketAddr>` (direct peer when no proxy is in front) → `"unknown"` fallback. Both `main.rs` files (CE and SaaS) switched to `into_make_service_with_connect_info::<SocketAddr>()` so the peer address actually reaches the extractor. Every audit call site passes `Some(ip.as_str())`, so the IP column in the viewer is meaningful from day 1.

  - **Viewer** — new `/admin/audit-log` page (Admin role only). Paginated table of `time | actor | action | target | details | IP`, newest first, with `per_page` default 100 (clamped to 10–500). Action codes get colour cues — red for `*.failure`, light red for `*.delete`, green for `*.create` — so a skim across hundreds of rows surfaces interesting events without filtering. Card header shows the retention figure and a "retained forever" hint when it is 0. Sidebar entry under Admin Settings, gated on `is_admin`. No filter dropdowns or CSV export in v1 — pagination only.

  - **Cross-tenant view for Superusers** — when the caller is a Superuser (the SaaS platform-admin role), the viewer drops the per-tenant `WHERE` filter and surfaces events across every tenant. A blue `Tenant` column appears between Time and Actor, the card header shows an "All tenants" warning badge, and the retention figure still reflects the admin's own tenant setting. Regular Admins stay scoped unchanged. Lets platform admins investigate customer incidents from the `default` tenant without SSH-ing into the DB.

  - **Retention setting in Admin Settings** — `Admin → Settings → General` gains an **Audit Log Retention (days)** numeric input next to the Schema Version chip. Accepts `0` (keep forever) or 1–10000 days. The help text links straight to `/admin/audit-log` so an admin tuning retention can jump to the viewer in one click. The value is read by the prune job on its next daily tick — no restart required.

  - **Daily prune** — `audit::prune()` runs from the scheduler's main loop once per UTC day (tracked by `last_audit_prune_day` vs `now.ordinal0()`). Reads each tenant's retention setting; tenants with `0` are skipped. The prune itself records one `audit.prune` row per tenant whose data was actually trimmed, with `{"removed":N,"retention_days":D}` in details, so the cleanup is itself auditable. Errors on one tenant don't block pruning for the rest. (The broader retention policy for `notifications` / `reports` / snapshots still waits for Task #9, but `audit_log` is fully handled.)

### Fixed
- **Tera template inheritance broke when a new template's name sorted alphabetically before `base.html`** — Tera 1.x validates `extends` parents eagerly at `add_raw_template` time, and `include_dir!`'s `.files()` iterator yields entries in alphabetical order. For years `base.html` happened to be the first file added (no template name started with `a`), so children that extend it could always resolve their parent. Adding `audit_log.html` (`au…` < `ba…`) put it ahead of `base.html` in the iteration and tripped `MissingParent { current: "audit_log.html", parent: "base.html" }` on startup. `init_tera_with_overrides` now explicitly looks up `base.html` via `TEMPLATES_DIR.get_file()` and registers it before the generic loop, then skips it in the loop. Idempotent and order-independent — removes a latent footgun where any future template starting with `a` would have hit the same wire.

---

## [0.4.0] - 2026-05-21

### Added
- **Agent auto-upgrade** — the server can now push a new client binary to registered systems without manual intervention.
  - **Server**: a new `agent_packages` table stores the platform, version, SHA-256 hash, and download URL for each available client binary. Client binaries are *embedded* into the server binary at compile time via `include_dir!` under `static/agents/`. On startup, `agents::startup_scan` iterates the embedded directory, hashes each `scmclient-{arch}-{os}[.exe]` over its in-memory bytes, and upserts the table. The existing public `/static/agents/{file}` route serves the downloads — no filesystem agents directory and no separate handler needed. Single-binary deployment.
  - **Systems list UI**: each system row now shows its `platform` (e.g. `x86_64-linux`) and, when a newer agent package is available, an amber **Upgrade → vX.Y.Z** button that queues an upgrade for that system. A new **Bulk Upgrade** action in the selection toolbar queues an upgrade for all selected systems simultaneously.
  - **Heartbeat protocol**: when a row with `command_type='UPGRADE'` exists in the `commands` table for a system, the next heartbeat response carries `"command": "UPGRADE"` with `upgrade_url`, `upgrade_sha256`, and `upgrade_version`. The UPGRADE command takes priority over pending TEST commands; the heartbeat clears only the UPGRADE row (leaving any queued tests intact so they re-dispatch after the client restarts on the new binary).
  - **Client**: handles the `UPGRADE` command by downloading the new binary, verifying the SHA-256 digest, atomically replacing itself via the `self_replace` crate, and then re-execing (Unix) or spawning itself and exiting (Windows).
  - **DB schema migration v17 → v18**: adds the `agent_packages` table, extends the existing `commands` table with a `command_type TEXT NOT NULL DEFAULT 'TEST'` column (UPGRADE rows have `test_id=NULL`), and adds a partial unique index `idx_cmd_upgrade_uniq` so each system has at most one queued upgrade. The `systems` table is unchanged — platform is derived on read from `arch + os`.
  - **Build pipeline**: restructured into three phases — `build-*-client` (all platforms in parallel) → `collect-agents` (renames raw binaries to the canonical `scmclient-{arch}-{os}[.exe]` scheme and stages a VERSION sentinel) → `build-*-server` / `build-docker` (downloads the agent bundle into `scmserver/static/agents/` before compiling so `include_dir!` embeds them into the resulting server binary).

- **Per-finding exclusions** — auditors can now suppress individual `(system, test)` results from compliance scoring. From the live policy report (`/policies/report/{id}`) or the live system report (`/systems/report/{id}`), an Editor right-clicks any result row to open a small context menu with **Exclude** (or **Unexclude** if the row is already excluded); the submission is one POST and the page reloads with the row showing a grey **EXCLUDED** badge instead of PASS/FAIL/NA. Excluded findings are treated as NA in scoring — removed from both numerator and denominator at every level (test, system, policy) — and persist permanently until the system or test is deleted (FK CASCADE). HTML + PDF + email + saved snapshots all flow the state through; archived views render frozen badges with no right-click menu. Three-way verdicts (Compliant / Non-Compliant / Not Applicable) are now correct in every PDF when a system's only failing finding is excluded. Implementation: new `excluded / excluded_by / excluded_at` columns on the existing `results` table (DB migration v18 → v19) — the heartbeat UPSERT only writes `result` + `last_updated` so re-running the policy never clears an exclusion. `scheduler::recalculate_current_compliance` updated to gate every PASS/FAIL/total tally on `r.excluded = 0`.

- **Result summaries on reports** — each card header (system on the policy report, policy on the system report) now shows four count badges — Passed / Failed / NA / Excluded — alongside the COMPLIANT / NON-COMPLIANT / NOT APPLICABLE chip. The PDFs of all four flavours print the same four counts in their summary tables. Counts are stored on `SystemReport` and `PolicyResultGroup` (`pass_count`, `fail_count`, `na_count`, `excluded_count`, all `#[serde(default)]` for older snapshots) and frozen into saved reports at save time. Old snapshots that pre-date these fields get their counts recomputed at view time from the saved results array so the NA column is accurate retroactively.

- **Policy report top card aligned with the system report** — the live policy report and the archive view now share the system-report layout: left side has the policy name + version + generated-by/date/system-count line + collapsible "View Policy Scope" test list; right side shows the four aggregate counts (Pass / Fail / NA / Excl) and a percent-compliant badge that uses the same SAT/Marginal/Non-Compliant thresholds the system report uses. `ReportData` gains `total_pass`, `total_fail`, `total_na`, `total_excluded`, and `compliance_score` (the percent of in-scope systems that are COMPLIANT among non-exempt systems; -1.0 → "Not Scanned"). The archive handler backfills the totals on the fly for snapshots saved before they existed.

### Fixed
- **Flash banners re-appeared on browser refresh** — success/error messages are carried across redirects via `?success_message=…` / `?error_message=…` query params. Once the page rendered, hitting browser refresh re-sent the same URL and the banner showed up again, making one-shot confirmations look sticky. A tiny inline script in `base.html` now calls `history.replaceState` on every render to strip both query params from the URL after the banner is shown, so the next refresh loads a clean URL with no banner. Affects every page that uses the shared layout, not just Systems.

- **Archive policy report's NA count was always 0 for older snapshots** — the per-system count backfill ran only when `pass_count == 0 && fail_count == 0`, which is a poor "old snapshot" marker because snapshots saved after pass/fail counts existed but before NA counts existed had non-zero pass/fail (skipping the backfill entirely) and therefore showed NA = 0 in both the per-system card and the top-card total. Backfill now runs unconditionally and recomputes all four counts from the saved results array, which is the actual source of truth.

---

## [0.3.10] - 2026-05-18

### Fixed
- **Scheduler notifications were silently dropped on fresh CE installs** — two places in `scheduler.rs` decided who to notify with a hard-coded `WHERE role = 'admin'` query:
  - `get_policy_owners` — emits the "Scheduled scan completed" / "Scheduled report saved" / "Scheduled X FAILED" notifications when a `policy_schedules` row fires
  - `check_for_updates` — emits the hourly "OpenSCM vX.Y.Z is available" notification when a newer release is detected on GitHub
  The bootstrap admin on a fresh CE install is stored with role `'superuser'` (see `install.rs`), so on a typical single-tenant install the queries returned an empty list and **no notification of any kind from the scheduler** ever reached the bell. Both queries now match `role IN ('admin', 'superuser')`. No data migration needed; effective on the next scheduler tick after restart.
- **Certificate icon floated awkwardly in policy list view** — the policy grid uses an inner `col-7` / `col-5` Bootstrap split inside each card for description vs. the big `fa-certificate` icon. In the 3-up Grid View each card is ~33% wide and the split looks right; switching to List View made each card span the full screen but left the inner column widths untouched, so the cert icon ended up centred in a ~40%-wide empty column halfway across the screen. Fixed by pulling the cert column out of the flex flow in list view and pinning it as a corner badge at the card's upper-right (`position: absolute; top: 8px; right: 12px`), shrinking from `fa-4x` to a 3rem font-size so it reads as a tight badge rather than a poster. The description column then stretches to 100% width with just enough right-padding to clear the badge. Click target preserved.

### Internal
- **`systems.rs` split into `systems.rs` + `groups.rs`** — `systems.rs` had grown past 1500 lines after the live-system-report and clickable-test-name features landed. The 6 group functions (`system_groups`, `system_groups_add[_save]`, `system_groups_delete`, `system_groups_edit[_save]`) are now in `scmserver/src/groups.rs`; everything that operates on the `systems` table itself stays in `systems.rs` (including `systems_bulk_add_group`, which is a bulk action that assigns systems to a group id — the action is on systems, the group is just a parameter). `fetch_system_report_data` and `fetch_tenant_tests_metadata` also stay in `systems.rs` since they're report helpers, not group-table operations. `lib.rs` registers the new `pub mod groups;` and reroutes the four `/system_groups/*` routes to `groups::*`; no URL paths change, no behaviour change.

  Result: `systems.rs` is now 983 lines, `groups.rs` is 599 lines.

---

## [0.3.9] - 2026-05-17

### Added
- **Email Me PDF — for all four report views.** Every report view page (archive policy, archive system, live policy, live system) now has an "Email Me PDF" button next to the existing "Download PDF" button. Clicking it POSTs to a new endpoint that generates the same PDF the download button would produce and sends it as an attachment to the logged-in user's account email. Available only when SMTP is configured — the button is rendered behind `{% if is_smtp_configured %}` and every handler re-checks SMTP server-side as defence in depth. PDF building was factored into `build_archive_policy_pdf` / `build_live_policy_pdf` (both returning `Result<Vec<u8>, ()>`) so the download and email paths share one source of truth per PDF flavour; the two system-PDF flows already used a shared `build_system_report_pdf`. New `Mailer::send_with_attachment(to, subject, html, filename, mime, bytes)` in `email.rs` builds a MultiPart/mixed message via lettre's `Attachment::new(filename).body(bytes, mime)` — no new crate dependency. Four new POST routes (`/reports/email/{id}`, `/reports/system/email/{id}`, `/policies/email/{id}`, `/systems/report/{id}/email`), all Viewer-gated like their download counterparts. Handlers share `reports::flash_back / user_email / report_email_body` helpers so the success/error wording is identical across endpoints.
- **Clickable test names on system compliance reports** — both the live system report (`/systems/report/{id}`) and the saved system snapshot (`/reports/system/view/{id}`) now make every test row clickable. Clicking pops the same detail modal the policy reports already use, showing the test's description, check procedure (rational), remediation, and current status. Test metadata is pulled live from the `tests` table via a new `systems::fetch_tenant_tests_metadata(tenant_id, pool)` helper — so even old saved snapshots get current descriptions. Rows whose test was renamed or deleted since the snapshot was saved fall through to plain text (no info icon, not clickable), the same graceful-degradation pattern the policy archive view already uses.
- **Hook for Policy Store update badge (CE side)** — new `set_store_update_provider(Arc<dyn Fn(&str) -> u32>)` registration function in `handlers.rs`, mirroring the existing `enable_saas_mode()` pattern. CE itself never registers a provider, so `store_update_count` is always 0 in `render_template` and the new template branch in `base.html` (`{% if store_update_count > 0 %}` red badge on the Policy Store sidebar link) stays hidden — exactly zero behaviour change for CE-only installs. SaaS registers a provider backed by an hourly background refresh so each tenant Admin sees how many of their installed policies have a newer version waiting in the store.

### Changed
- **Database reset is now an Admin action, scoped to the caller's tenant** (was Superuser-only). The reset SQL was already filtering by `auth.tenant_id` end-to-end, so dropping the role gate from Superuser to Admin only widens *who* can invoke it — an Admin can wipe their own tenant's systems / groups / tests / policies / reports / users, and nothing else. Superuser still has every Admin power (`Superuser > Admin`), so the CE single-tenant case and the SaaS platform-admin-of-`default`-tenant case keep working unchanged. Template gates split so the Email tab stays Superuser-only (SMTP is platform-global in SaaS) while the Danger Zone tab / card / confirmation modal move to `is_admin`. UI copy clarified: "all data **for this tenant**…" / "**for this tenant only**…" so a tenant Admin doesn't fear wiping the platform.
- **PDF policy report — "Tests in this Policy" now starts on its own page** (both archive and live PDF flows). The 1.0-unit `Break` before the section is replaced with a hard `PageBreak`, so page 1 is just the cover (title + submitter + logo + Report Details) and page 2 begins the test catalog. The existing PageBreak after the catalog (separating it from the per-system breakdown) is unchanged. Legacy archive reports with empty `tests_metadata` skip both the section and its new PageBreak, so their layout is unaffected.

### Fixed
- **Editing the bootstrap admin's name or email aborted with "The bootstrap admin role cannot be changed"** — the v9 trigger `protect_bootstrap_admin_role` was declared `BEFORE UPDATE OF role`, which in SQLite fires whenever the `role` column appears in the UPDATE statement's SET clause regardless of whether the value actually changes. The user-edit handler always re-passes the current role to keep one canonical UPDATE shape, so editing only name/email of `users.id = 1` (default tenant) tripped the trigger. Trigger rebuilt with an additional `AND NEW.role != OLD.role` guard in its WHEN clause; new schema migration **v16 → v17** drops and recreates it on already-upgraded installs, the fresh-install path and the v8→v9 source both updated to match. The guarantee (you can never *change* the bootstrap admin's role) is preserved.
- **v16 → v17 migration crashed on startup with "trigger protect_bootstrap_admin_role already exists"** — the migration's `DROP TRIGGER IF EXISTS` and `CREATE TRIGGER` were executed through the `&SqlitePool` reference, so sqlx was free to grab a different pooled connection for the CREATE. The CREATE's prepared-statement compilation on the second connection could still see the pre-DROP schema state and refuse to create the trigger. Fixed by pinning both DDL statements to a single acquired connection (`pool.acquire()` once, then `&mut *conn` for each query), so the DROP/CREATE pair lands on the same SQLite session and the schema change is visible to the CREATE.
- **"Email Me PDF" silently succeeded on archive report views** — the new email handlers redirected to `/reports/view/{id}?success_message=…` and `/reports/system/view/{id}?success_message=…` on success, but the matching view handlers (`reports_view`, `system_reports_view`) never read the query string, so the flash was thrown away before reaching the template. The two archive templates were also missing the `{% if success_message %}` alert block (`reports_view.html`) or both flash blocks (`system_report_view.html`). Fixed by adding `Query<ErrorQuery>` to both handlers and inserting `success_message` / `error_message` into the template context, plus adding the matching alert markup to both templates. The two live-report views (`policies_report`, `system_report`) already had this wired through.

### Hardening
- **`run_migrations` documents the single-connection rule for multi-DDL migrations** — top-of-fn comment explains when to use `pool.begin()` vs `pool.acquire()` vs plain `&SqlitePool`, so the next migration author doesn't repeat the v16→v17 mistake. The rule applies to any step that issues ≥ 2 dependent DDL statements (DROP+CREATE of the same object, ALTER ADD COLUMN followed by an UPDATE that references the new column, RENAME COLUMN followed by a SELECT on the new name).
- **v13 → v14 and v14 → v15 wrapped in transactions preemptively** — both ALTER ADD COLUMN + per-row backfill. They've run fine in the field, but they're structurally the same shape that bit v16→v17 in theory. Switched from `pool` to `pool.begin()` + `&mut *tx`. Side benefit: each step is now atomic — if the backfill fails partway through, the ALTER rolls back too, so the migration can be retried cleanly.

---

## [0.3.8] - 2026-05-17

### Changed
- **`offline_threshold` setting now stored in minutes (was seconds)** — aligned with `auto_prune_inactive`, which was already minutes, so both fields use the same unit and a quick visual comparison is meaningful (e.g. "mark offline after 60 min, delete after 1440 min"). Default changed from `3600` (s) to `60` (min) — same effective duration. The Admin Settings page label now reads "Offline Threshold (minutes)" with `min="1" max="1440"` on the input. `systems.rs` multiplies by 60 at SQL bind time, matching how `prune_inactive_systems` has always handled `auto_prune_inactive`. Schema migration **v15 → v16** divides every existing tenant's stored value by 60 (integer division, clamped to a minimum of 1) so upgrade is a no-op for the user — the column unit changes but the behaviour stays the same.

### Added
- **Delete Test button on the test edit page** — editors can now delete a test directly from `/tests/edit/{id}` without going back to the list, via a red `Delete Test` button on the left of the card footer. Uses the existing `GET /tests/delete/{id}` route (ON DELETE CASCADE already removes its conditions and unlinks it from policies); confirm dialog warns about the policy-unlink consequence.
- **PDF report — Tests Summary on the first page** — both policy report PDFs now render a `Tests in this Policy (N)` section directly after the Report Details table, listing every test's name and description in a two-column bordered table:
  - **Archive PDF** (`GET /reports/download/{id}`) reads the `tests_metadata` JSON already persisted on save — no schema change, every newly-saved report gets it; legacy reports without `tests_metadata` skip the section cleanly.
  - **Live PDF** (`GET /policies/report/download/{id}`) builds the same section from a fresh DB query, so it always reflects current test definitions.

  The per-system breakdown that follows is unchanged. The system-scoped PDF (`/systems/report/download/{id}`) is unaffected — it shows multiple policies per host and already lists tests per-policy.

---

## [0.3.7] - 2026-05-16

### Added
- **`apply_policy_import(pool, tenant_id, export)` extracted from `policies_import`** — the per-test upsert + conditions-replace + unlink logic now lives in one reusable async fn returning a structured `PolicyImportSummary { policy_id, action, inserted_tests, updated_tests, unlinked_tests }`. The existing multipart `POST /policies/import` is now a thin wrapper around it; SaaS's new Policy Store install/update handler uses the same core so the import semantics stay identical no matter where the file came from.
- **`is_saas` sidebar entry: Policy Store** — new `base.html` link to `/store` gated on `is_saas and is_editor`. CE renders nothing (flag defaults to false) so behaviour is unchanged for the CE edition.

### Fixed (scmclient)
- **Tests with no server-assigned id were silently dropped** — `process_compliance_tests` defaulted to `test_id=0` and POSTed a result the server silently ignored. Now skips the test with a `warn!` so the issue is visible in agent logs.
- **Panic-free DNS failure in `get_system_domain`** — on Windows the inner `getaddrinfo` iterator called `.unwrap()` on the `AddrInfo` result; replaced with `.ok()?` so a failed DNS lookup returns `None` instead of panicking.
- **Config file written on every load even when unchanged** — `get_config()` unconditionally re-saved the file after each `normalize()` call, causing pointless disk writes and mtime churn that could confuse file-integrity monitors. `normalize()` now returns `(Config, changed: bool)`; callers save only when `changed` is true.

### Changed (scmclient)
- **`reqwest::Client` built once and reused across heartbeats** — the HTTP client was reconstructed every heartbeat cycle, discarding reqwest's connection pool and TLS session cache. Client is now built once in `main()` and passed by reference to `send_system_info`, giving persistent TCP+TLS reuse at no behaviour cost.
- **`send_system_info` decomposed into four named helpers** — the 200-line heartbeat function now delegates to `load_or_create_identity`, `collect_system_info`, `post_heartbeat`, and `dispatch_server_command`; the top-level function reads as a 12-line flow. No behaviour change.
- **Generic `calculate_hash::<H>` replaces duplicate SHA helpers** — `calculate_sha1` / `calculate_sha2` were byte-for-byte identical loops differing only in hasher type; collapsed into one generic function. `file` and `directory` owner/group/permission arms unified through shared `check_path_owner` / `check_path_group` / `check_path_permission` helpers, eliminating six near-identical 15-line blocks.

---

## [0.3.6] - 2026-05-16

### Fixed
- **`init_tera_with_overrides` crashed on startup when an override extended `base.html` and base.html was not itself an override** — Tera 1.x validates `extends` parents at `add_raw_template` time, but the loader added overrides *before* CE templates. As long as `base.html` was in the override list (its previous SaaS use), the order accidentally worked; once SaaS started inheriting CE's `base.html` directly, the first child override (`admin_tenants.html`) failed with `MissingParent { current: "admin_tenants.html", parent: "base.html" }` and `main()` returned `Err`, causing the SaaS service to crash-restart in a tight loop. Reversed the loader order — CE templates load first; overrides replace them by name afterwards.

---

## [0.3.5] - 2026-05-16

### Added
- **`is_saas` template context flag** — new `scmserver::handlers::enable_saas_mode()` lets the SaaS binary flip a process-wide flag at startup. `render_template` exposes it as `{{ is_saas }}` so SaaS-only chrome (tenant chip, Support menu, Platform Admin treeview) can live directly in the shared `base.html` instead of forking the whole template. CE rendering is unchanged (flag defaults to `false`).

### Fixed
- **Stale `comparison` template references** — `tests.html` and `tests_edit.html` still read `tc.comparison` / `ac.comparison` after the v11→v12 column rename, causing a "Variable not found in context" render error whenever a tenant had any test conditions or applicability rules. Renamed all four references back to `condition`.

---

## [0.3.4] - 2026-05-16

### Added
- **Policy Import / Export** — every policy now has a stable `external_id` (32-char hex) and an optional `author` field. New `GET /policies/export/{id}` downloads a JSON file containing the policy, every linked test, and each test's conditions/applicability rules — ids and tenant references are stripped so files are portable across installations. New `POST /policies/import` (multipart upload) restores a file: if the `external_id` matches an existing policy in the tenant, the policy is updated; otherwise it is inserted as a new policy with name-collision handling (`(imported)`, `-2`, `-3`, …). Import button and per-policy export icon added to the policies page; author shown on each policy card and editable from the add / edit forms.
- **Per-test stable identity (`tests.external_id`)** — tests now also carry a 32-char hex `external_id`, auto-generated on creation and exported alongside each test. On import, tests are matched by `external_id`: a match updates the existing row in place (preserving results history and any cross-policy links) and replaces its conditions; no match inserts a new test. Tests previously linked to the policy but absent from the imported file are **unlinked** from this policy (but kept in the tests table) so re-imports become non-destructive across policies. Export format bumped to v3; older v1/v2 files still importable (missing test ids are generated).

### Changed
- **Schema version bumped to 15** — v13→v14 adds `policies.author` and `policies.external_id` and backfills existing policies; v14→v15 adds `tests.external_id` and backfills existing tests; fresh installs stamp at v15.
- **axum `multipart` feature enabled** — required by the new policy import endpoint.

---

## [0.3.3] - 2026-05-15

### Fixed
- **Offline badge missing on Systems page after DataTables redraw** — the offline indicator (row dimming + "Offline" badge) was applied via jQuery on document ready, so any DataTables interaction (search, sort, pagination) wiped it out for the affected rows. Moved the badge into the Tera template so it renders server-side as part of the cell, and replaced the JS-applied row dimming with a pure CSS rule (`tr[data-offline="true"] td:not(:last-child) { opacity: 0.5; }`) that survives DOM redraws.
- **Agent results not stored — `missing field 'type'` deserialization error** — the v10→v11 MySQL-compatibility migration renamed `test_conditions.type` → `ctype` and `test_conditions.condition` → `comparison` on the server, but the scmclient agent still expected the original JSON field names. Every heartbeat that returned tests caused the agent to fail deserializing, so no compliance results were ever sent back. Fixed by reverting both columns to their original names (`type`, `condition`) via a new v11→v12 migration; the Rust struct field names match again so the JSON wire format is identical to what the agent expects, with no `serde(rename)` shims.

### Added
- **Auto-delete inactive systems** — new admin setting `auto_prune_inactive` (in minutes) automatically removes active systems whose `last_seen` is older than the configured threshold. `0` disables the feature (default). Runs every 60 seconds inside the existing scheduler loop. Per-tenant setting, exposed in the General tab of the Admin Settings page.

### Changed
- **`test_conditions.type` and `test_conditions.condition` restored** — the MySQL-era column names (`ctype`, `comparison`) reverted to the originals via migration v11→v12. SQLite identifier quoting (backticks) used in raw SQL where `type` collides with parser keywords. No external API change.
- **Schema version bumped to 13** — fresh installs are stamped at v13; existing installs run the new v11→v12 (column rename) and v12→v13 (seed `auto_prune_inactive` for all tenants) migrations on startup.

---

## [0.3.2] - 2026-05-15

### Changed
- **`db_compat` module deleted** — the entire multi-backend compatibility shim is removed. All 52 `adapt_sql()` call sites converted to direct SQL literals; remaining helpers (`format_datetime_col`, `unix_diff_col`, `date_group_col`, `group_concat_col`, `last_insert_id_sql`, `upsert_*_sql`, `admin_role_trigger_sql`, `rename_table_sql`, `table_exists_sql`) inlined at their call sites; `column_exists` moved as a private function into `schema.rs`.
- **`render_template` DB round-trips halved** — the four per-page queries (pending count, notify count, notifications list, tenant name) batched into two: a single sub-select retrieves pending count + tenant name; a window-function query retrieves notifications + total count simultaneously.
- **`initialize_database` split into focused helpers** — the 560-line function broken into three private helpers (`create_tables`, `create_indexes`, `seed_lookup_data`) called by a thin coordinator.
- **`recalculate_current_compliance` split into focused helpers** — the 195-line aggregation function broken into `purge_ghost_results`, `update_test_stats`, `update_system_stats`, `update_policy_stats`, all sharing one transaction.
- **Compliance verdict centralised** — `handlers::is_system_passed(pass, fail)` replaces the inline `fail_count == 0 && pass_count > 0` expression in `reports.rs`, `policies.rs`, and `systems.rs`.
- **Stale comments removed** — scaffolding annotations (`// <--- ADD THIS LINE`, `// Added`, `// Alias for …`) cleaned from `models.rs`; `lib.rs` header updated to remove EE references.

---

## [0.3.1] - 2026-05-15

### Changed
- **SQLite-only — MySQL and PostgreSQL support dropped** — CE reverts to `sqlx::SqlitePool` exclusively. The multi-backend `AnyPool`, `DbBackend` enum, `set_db_backend`, `MYSQL_SUPPORT`, and `row_get_string` / `row_get_opt_string` helpers have been removed.
- **SaaS drops EE dependency** — SaaS (0.2.2) now depends directly on `scmserver` (CE) instead of `openscm-ee`. `create_core_router` replaces `create_ee_router`. The admin→superuser promotion migration is inlined in SaaS `main.rs`. The `sqlx` feature set is trimmed back to `sqlite` only.

### Fixed
- **Unscanned tests shown as FAIL in system compliance report** — tests with no entry in the `results` table were mapped to `"FAIL"` by `normalize_status()`. Added a `"not_scanned"` arm so unrun tests are counted in the N/A bucket and rendered as the grey *Not Scanned* badge.

---

## [0.3.0] - 2026-05-14

### Added
- **MySQL and PostgreSQL support (EE / SaaS)** — EE and SaaS can now connect to MySQL or PostgreSQL instead of SQLite by setting `db_type = "mysql"` / `"postgres"` and the corresponding `mysql_url` / `postgres_url` in the server config. SQLite remains the default; existing installs require no configuration change.
- **`db_compat` module** — new backend-agnostic SQL helper library used by all query sites: `adapt_sql` (rewrites `AUTOINCREMENT`, `INSERT OR IGNORE`, `DEFAULT datetime('now')`), `last_insert_id_sql`, `format_datetime_col`, `unix_diff_col`, `date_group_col`, `group_concat_col`, `table_exists_sql`, `upsert_results_sql`, `upsert_schedule_sql`, `upsert_setting_sql`, `rename_table_sql`, `column_exists`, `schema_info_exists_sql`, and `admin_role_trigger_sql`. Each emits the correct SQL dialect for SQLite, MySQL, or PostgreSQL.
- **`DatabaseConfig` multi-backend fields** — `db_type`, `mysql_url`, and `postgres_url` added to the server config struct.

### Fixed
- **Bootstrap admin created with wrong role on fresh CE install** — the initial admin user was assigned role `admin` instead of `superuser`, leaving no superuser on a brand-new CE installation. Fixed to assign `superuser` at install time.
- **All-NA policy verdict shown as FAILED** — when every test result for a system was NA, both the live policy report and archived policy report showed FAILED / NON-COMPLIANT. Both views now show a grey "NOT APPLICABLE" state, consistent with the existing system-level report behaviour.
- **Archived policy reports failed to load after schema update** — reports saved before `pass_count` / `fail_count` were added to `SystemReport` crashed with `missing field` on deserialization. Fixed with `#[serde(default)]` on both fields plus a backfill step that recomputes counts from the stored results vec.
- **Agent re-registration loop after server DB reset** — the `INSERT … SELECT last_insert_rowid()` sequence was not atomic through AnyPool, causing the rowid to always return 0 and the agent to re-register on every heartbeat. Wrapped in a transaction to make it atomic.
- **Stale server public key caused permanent signature verification failure** — after a server DB reset (new signing keys), clients holding the old cached server public key failed all signature checks indefinitely. The client now drops the stale key file on first verification failure and re-handshakes on the next heartbeat.
- **Non-deterministic wire format broke Ed25519 signatures** — `#[serde(flatten)]` on `TestWithConditions` produced inconsistent JSON key ordering when serialized for signing. Replaced with a flat `TestPayload` struct for deterministic serialization.
- **AnyPool DATETIME decode error** — AnyPool could not decode `DATETIME` columns directly. All affected queries now `CAST` datetime columns to `TEXT` before binding to Rust `String` fields.
- **`PolicySchedule.enabled` Bool type mismatch** — AnyPool maps `BOOLEAN`/`INTEGER` to `BIGINT`; changed the field from `bool` to `i64` and added `CAST(enabled AS INTEGER)` in all schedule queries. Tera templates treat `0`/`1` as falsy/truthy.
- **`SELECT EXISTS(…)` returned BIGINT not bool** — `query_scalar::<_, bool>` for existence checks failed at runtime. Changed to `i64` with `.unwrap_or(0) > 0`.
- **`email_verified` column referenced in CE login query** — CE's login handler referenced a SaaS-only column, causing SQL errors. Column reference removed from CE.
- **Severity prefix cluttered test selection in Add Policy form** — removed the `[SEVERITY]` prefix from test options in the dual-listbox so only the test name is shown.
- **macOS client config file path incorrect** — fixed the config file lookup path on macOS.
- **PostgreSQL `DATETIME` type unsupported** — `adapt_sql()` now converts `DATETIME` column declarations to `TIMESTAMP` for PostgreSQL; without this all `CREATE TABLE` statements would have failed on PG.
- **PostgreSQL `column_exists()` used native `$1`/`$2` placeholders** — AnyPool requires `?` for all backends; using `$1`/`$2` directly caused a runtime panic during the v3→v4 migration on PostgreSQL.
- **MySQL `ALTER TABLE … RENAME TO` syntax unsupported** — the v2→v3 schema migration used SQLite/PostgreSQL rename syntax. Replaced with a new `db_compat::rename_table_sql()` helper that emits `RENAME TABLE … TO` on MySQL.

### Internal
- **CE AnyPool migration** — CE core (`scmserver`) migrated from `SqlitePool` to `AnyPool` throughout. All SQLite-specific SQL in `client.rs`, `dashboard.rs`, `install.rs`, `policies.rs`, `schema.rs`, `settings.rs`, `systems.rs`, and `tests.rs` replaced with `db_compat` helpers. `sqlx` Cargo features extended to include `mysql` and `postgres` so all drivers are compiled in.
- **EE multi-backend pool** — EE `main.rs` reads `db_type` from config, sets `DbBackend` at startup, and connects to the appropriate backend. SQLite PRAGMAs are guarded behind a backend check.
- **SaaS multi-backend pool** — SaaS aligned with EE: `main.rs` now reads `db_type` from config and supports SQLite (default), MySQL, and PostgreSQL. All SaaS source files migrated from `SqlitePool` to `AnyPool`.

---

## [0.2.8] - 2026-05-11

### Added
- **Linux client for s390x (IBM Z / LinuxONE)** — `scmclient` is now built and packaged (deb + rpm) for `s390x-unknown-linux-gnu`. The server is not yet supported on s390x.
- **Linux client for LoongArch64** — `scmclient` is now built and packaged (deb + rpm) for `loongarch64-unknown-linux-musl`, targeting LoongArch-based servers.
- **Linux client for i686 (32-bit x86)** — `scmclient` is now built and packaged (deb + rpm) for `i686-unknown-linux-musl`, covering legacy 32-bit x86 servers.

### Internal
- **Source code documentation** — all 15 `scmserver` source files now carry a file-level description header and a per-function banner documenting the HTTP route, purpose, and minimum required role. No behaviour change.

---

## [0.2.7] - 2026-05-10

### Fixed
- **NA results rendered as FAIL in PDF reports** — the per-rule breakdown in PDF exports showed NA results in red with "FAIL" text. They now render in grey with "NA" text, matching the on-screen report view.
- **`is_passed` verdict incorrect for saved reports** — when saving a report, the system pass/fail verdict is now consistent with the live policy report view: a system is compliant only when it has no FAIL results **and** at least one PASS. Systems where every test returned NA are correctly marked as non-compliant.
- **Admin Settings save silently discarded for tenants without pre-seeded rows** — the settings save handler used `UPDATE`, which affects 0 rows when no settings exist yet (e.g. new SaaS tenants). Changed to `INSERT … ON CONFLICT DO UPDATE` so settings are always written regardless of whether rows pre-exist.
- **Windows installer missing Organization field** — the custom installer page only asked for Server URL and hardcoded `Organization = default`. SaaS users had to manually edit the registry after installation. The installer now asks for both Server URL and Organization, pre-filled from the existing registry values on upgrade.

---

## [0.2.6] - 2026-05-07

### Added
- **Superuser role** — new role level above Admin that grants access to platform-level tenant management. The initial admin user is automatically promoted to Superuser on first EE/SaaS startup. Superuser can be assigned to other users via the Users page.
- **Tenant management (EE/SaaS)** — Superusers can list, create, view, suspend, activate, and delete tenants via the new Platform Admin section in the sidebar. The `default` and `platform` tenants are protected from suspension or deletion.
- **Organization field on EE login page** — multi-tenant users can now specify their organization at login. Leaving the field blank logs in as a platform-level (Superuser) account.
- **Tenant user management (EE/SaaS)** — Superusers can add new users to a tenant, edit their name/email/role, reset their password, and delete them — all from the tenant detail page via inline modals. No separate pages required.
- **SMTP email relay (CE/EE/SaaS)** — Admin Settings now has an Email tab for configuring an SMTP relay (host, port, TLS mode, credentials, from address, app URL). In SaaS, if SMTP is configured new users must verify their email before logging in; if not configured, accounts are activated immediately. Replaces the previous Resend API key approach.
- **Bootstrap admin protection** — the initial admin account (id=1, default tenant) is now protected from role changes at three layers: the edit UI shows a disabled lock icon, the server always preserves the DB role regardless of submitted form data, and a SQLite trigger (`protect_bootstrap_admin_role`) raises an abort if any code path attempts a direct update. Schema migration v8→v9 adds the trigger to existing installations.
- **Clean Database action** — Superusers can permanently delete all operational data (systems, groups, tests, policies, reports, scan results, users) while preserving the admin account, settings, SMTP configuration, and signing keys. Requires typing `RESET` to confirm. Located in the new **Danger Zone** tab in Admin Settings.
- **Danger Zone tab in Settings** — Superuser-only tab that consolidates destructive actions, replacing the previous card appended at the bottom of the page.
- **Plan field on tenants (EE/SaaS)** — tenants now have a `plan` field (`free`, `starter`, `pro`, `enterprise`) used by EE/SaaS to enforce per-plan resource limits. CE is unaffected.
- **Platform Admin → Plans page (EE/SaaS)** — Superusers can configure the maximum number of systems, groups, policies, and reports per plan. Zero means unlimited. Accessible from the Platform Admin sidebar section.
- **Plan limit display on dashboard (SaaS)** — the Active Inventory, Active Policies, and Scan Reports info boxes now show the current count alongside the plan limit (e.g. "5 of 25"). Displays "Unlimited" when the plan limit is set to 0. Invisible in CE where the `plan_limits` table is absent.

### Fixed
- **SMTP settings are now global** — SMTP configuration (`smtp_*` keys and `app_url`) is always read from and written to the `default` tenant, regardless of which tenant the logged-in user belongs to. This fixes support ticket and verification emails in SaaS where the platform admin (in the `platform` tenant) previously saved settings that `Mailer` could not find.
- **Account locked out if verification email fails (SaaS)** — if SMTP is configured but the verification email cannot be delivered, the account is immediately activated so the user can still log in. A clear message is shown on the login page explaining what happened.
- **NA results counted as failures in policy report view** — when saving a report, any NA result incorrectly flipped the system verdict to Non-Compliant. Only explicit FAIL results now affect the verdict.
- **NA results counted as violations in policy PDF report** — the violation count in the PDF summary used `total − PASS`, which included NA. It now counts only FAIL results. NA tests also now render as grey "N/A" in the per-rule breakdown instead of red "FAIL".
- **ARM7 deb packages missing from releases** — the CI build workflow used `ARCH=arm7` which is not a valid dpkg architecture. Fixed to `ARCH=armhf` so `.deb` packages are correctly built and published for ARMv7.
- **Superuser role rejected when adding a new user** — the server-side role allowlist was missing `superuser`, causing the form submission to return "Invalid role selected" even for a legitimate value.
- **Role descriptions missing in user edit form** — the role dropdown in the edit form now shows the same human-readable labels as the add form (e.g. "Administrator (Full System Access)"). Role select width also increased to 340 px so full descriptions are visible.

---

## [0.2.5] - 2026-05-05

### Added
- **System compliance report snapshots** — save and download (PDF) archived compliance reports per system. The Reports page now has two tabs: Policy Reports and System Reports.
- **Policy coverage list in system report** — the system header card now shows a collapsible "View Policy Coverage" section listing all policies the system is under, with their descriptions. Mirrors the "View Policy Scope" section in the policy report.
- **Policy description in system report cards** — each per-policy card in the system report shows the policy description below the test table when one is set.
- **PDF download from live system report** — a "Download PDF" button is now available on the live system compliance report page, matching the existing button on the live policy report. The PDF includes policy descriptions.
- **"View Live Report" button on saved report pages** — archived policy and system report snapshots now include a "View Live Report" button linking back to the current live report. If the policy or system has since been deleted, the button is replaced with a greyed-out "Policy Deleted" / "System Deleted" badge.

### Fixed
- **Database indexes not applied on existing installs** — the 11 composite indexes added in v0.2.3 were only created by the first-run installer, so upgraded installs never received them. They are now applied via the v6→v7 migration on the next server startup.
- **Post-save redirect** — saving a compliance report (policy or system) now returns to the same live report page with a success banner, instead of redirecting away to the Reports list or Policies list.
- **Offline row dimming no longer greys action buttons** — in the Systems table, the opacity/greyscale effect now applies only to data cells; the action buttons in the last column stay fully opaque and remain clickable.
- **Dashboard report count includes system reports** — the Reports counter on the dashboard now sums both policy reports and system compliance report snapshots.
- **Fresh install unnecessarily ran all migrations** — a new installation stamped `schema_info` at version 0, causing all 7 migrations to execute on first startup. Fresh installs now stamp the current schema version directly so no migrations are needed.
- **Navigating to a deleted system or policy report now redirects gracefully** — previously returned a blank 404; now redirects to the Systems or Policies list with a "not found" error banner.
- **Consistent report action buttons** — all four report pages (live policy, live system, archived policy, archived system) now use identical button labels, icons, colours, and order: Back · Download PDF · Save Report · View Live Report.
- **PDF cell padding** — all table cells in every PDF report now have uniform padding so text no longer touches the cell border lines.
- **PDF disclaimer page** — all PDF reports (live policy, archived policy, live system, archived system) now end with the disclaimer on its own dedicated last page, at font size 10, prefixed with "Note:".

---

## [0.2.4] - 2026-05-04

### Fixed
- **v0.2.2 clients rejected with 401 after server upgrade to v0.2.3** — the signature verification function re-serialized the deserialized payload struct before checking the signature. When a v0.2.2 client sent the wire field as `tenant_id`, the server deserialized it into the renamed `organization` field and re-serialized it back — producing different JSON bytes from what the client had signed, causing every pre-v0.2.3 client to be rejected. Fixed by verifying signatures against the raw received JSON bytes rather than a re-serialized struct. All client versions are now accepted by the same server.
- **FreeBSD service stops silently after crash** — the RC script now uses `daemon -r -R 10` so the service automatically restarts after any unexpected exit with a 10-second cooldown. Previously a single crash would leave the service permanently stopped with no indication.
- **FreeBSD agent exits when local IP cannot be determined** — a failed `local_ip_address` lookup no longer aborts the heartbeat cycle. The agent logs a warning and continues with `0.0.0.0`, allowing it to keep running when the network interface is temporarily unavailable.

---

## [0.2.3] - 2026-05-03

### Added
- **CMD enabled warning** — scmclient logs a warning at startup when `cmd_enabled = true` to alert operators that the client will execute commands received from the server.

### Changed
- **`tenant_id` renamed to `organization`** — the client config field, Windows registry key, and wire protocol now use `organization` instead of `tenant_id`, aligning with standard terminology. The server accepts both names for backward compatibility with older clients. Existing config files and registry entries are migrated automatically on first run.
- **Self-healing config on every startup** — the client normalizes and rewrites its config on every startup. Missing settings are filled in with defaults, stale or renamed keys are removed, and legacy field names are rewritten in canonical form. Upgraded clients will automatically gain any new settings added in future releases.

### Fixed
- **CMD element captures stderr** — commands that write to stderr instead of stdout (e.g. macOS `softwareupdate`) now evaluate correctly against OUTPUT conditions. Previously they always returned False.
- **Policy verdict when all tests are NA** — a policy where every test returned NA (e.g. no applicable OS tests, or `cmd_enabled = false`) previously showed as COMPLIANT / PASSED. It now correctly shows as NOT APPLICABLE with a grey badge.

### Performance
- **Database indexes** — 11 composite indexes added covering the most frequent query patterns (results by tenant/test, systems by tenant/status/score, compliance history, notifications, reports). Existing installs gain the indexes automatically on first startup with no migration required.
- **SQLite WAL mode** — server now opens the database with WAL journal mode, `synchronous=Normal`, and a 5-second busy timeout. Readers no longer block writers, write throughput improves, and concurrent requests queue instead of returning an immediate busy error.

### SaaS
- **`[email]` config section** — new optional config block (`resend_api_key`, `from_address`, `app_url`) used by the SaaS edition for transactional email. CE and EE ignore it entirely.
- **`email_verified` user flag** — schema migration v5→v6 adds `email_verified` column to the users table (default `1` for all existing CE/EE users). The SaaS edition uses this to gate login until the user's email address is confirmed.

### Build
- Windows installer filename no longer includes the redundant `windows` label — e.g. `scmclient-0.2.3-1-x86_64.exe`.
- GitHub Actions workflow changed from draft to published release.

---

## [0.2.2] - 2026-05-03

### Added
- **System compliance report** — new live report page (`/systems/report/:id`) showing every policy the system belongs to, with each test result (PASS / FAIL / NA) grouped per policy. Includes overall pass/fail/NA counters and a per-policy verdict.
- **Dashboard drill-down for systems** — Top Failed Systems table now links directly to the system compliance report on click, matching the existing behaviour of the Top Failed Policies table.
- **Compliance report button** — green clipboard button added to each active system row in the Systems table for one-click access to the system report.
- **Policy report link from dashboard** — Top Failed Policies table now links directly to the live policy report.

### CI / Build
- Replaced manual build script with GitHub Actions workflows triggered on version tag (`v*`).
- **Stable workflow** builds all targets, packages deb / rpm / archlinux / Windows exe / macOS pkg / FreeBSD pkg, pushes a Docker multi-arch image (amd64 + arm64) to Docker Hub, and creates a draft GitHub Release with all artifacts attached.
- **Testing workflow** (manual trigger) builds and packages all targets for validation without publishing.

### Fixed
- Error 500 on system groups add and edit pages.

---

## [0.2.0] - 2026-04-30

### Added
- **First-run setup screen** — a guided account-creation page is shown on the first visit to a fresh installation, replacing the previous default `admin/admin` credentials and the associated warning message in package scripts.
- `init_tera_with_overrides()` — public function that loads all CE templates then lets callers substitute individual templates by name. Used by EE and SaaS to inject custom pages without forking CE.
- Optional `organization` field in `LoginForm` — if provided, scopes the user lookup to that tenant and returns a clear "Organization not found" error if unknown. CE and EE are unaffected (field is absent from their login form). Powers SaaS multi-tenant login.
- `success_message` support added to the login page context (used by SaaS to confirm account creation after registration).

### Changed
- Schema migrated to **v4** — test applicability conditions moved from inline JSON columns to a dedicated `test_conditions` table, enabling indexed lookups and cleaner per-condition management.
- `create_core_router` refactored into `build_core_routes` + `apply_core_layers` helpers; later simplified once the optional `organization` login approach was adopted.
- Server public key is now included in the heartbeat response **only** when the agent explicitly requests it (i.e. when `public_key` is present in the payload). Previously the key was sent on every heartbeat regardless. The REGISTER response also now correctly includes the server public key for initial key exchange.

### Fixed

**Server**
- Policy schedule edit page always showing scan and report schedules as disabled after saving — `schedule_type` column was missing from the SELECT query, causing a silent sqlx decode failure.

**Agent**
- macOS client service not restarted after package upgrade — `preinstall` script added to stop the running service before Payload extraction; `postinstall` now uses `launchctl enable` + `bootstrap` (with fallback to `load -w`) so the service is reliably re-enabled on Sonoma and later.
- Arch Linux client service not restarted after upgrade — installer scripts now correctly detect the pacman version-string argument (e.g. `0.2.0`) passed by nfpm/pacman hooks, where Debian/RPM pass `configure`/`1`/`2`. Dedicated Arch `.install` files added for PKGBUILD/AUR packaging.
- macOS package detection — Homebrew (`brew list`) and `pkgutil` are now checked for package existence and version, covering packages installed outside the App Store.
- False `ERROR` log when a file-content check is run against a path that does not exist — the check now returns `false` silently (logged at `DEBUG`) instead of attempting to open the file and logging an OS error.

### Security
- Resolved all high, medium, and low-severity findings from a full code review of the server and agent codebases (`receive_result`, input validation, error handling, and two additional high-severity gaps in result ingestion).

---

## [0.1.9] - 2026-04-28

### Added
- **Bulk actions** — Systems: approve, add to group, delete. Tests: delete, add to policy. Reports: delete. All actions operate on user-selected rows across any page of the table.
- **Version update notifications** — server checks the GitHub releases API hourly and sends a dismissible in-app notification to all administrators when a newer version is available. Deduplicates notifications so admins are only alerted once per version.

### Changed
- Pinned Rust toolchain to 1.95.0 via `rust-toolchain.toml` for reproducible builds.

### Fixed
- Missing tooltips on action buttons in the Tests table.

---

## [0.1.8] - 2026-04-14

### Added
- **CMD element** — new test element type that runs a shell command and evaluates its output against a string condition. Disabled by default; opt in with `cmd_enabled = true` in client config so admins explicitly permit command execution on agents.
- **Username duplicate check** — creating a user now fails with a clear error if the username is already taken.

### Changed
- `scmserver` refactored into a library crate (`lib.rs`) with a thin `main.rs` entry point, enabling the Enterprise Edition binary to depend on it directly.
- CMD element output field renamed from `stdout` to `output`.

### Fixed
- Package existence check on Debian/Ubuntu now inspects dpkg output text instead of exit code (exit code is always 0, masking uninstalled packages).

---

## [0.1.7]

### Added
- **Arch Linux agent support** — `pacman` package manager added to package existence and version checks.
- **Arch Linux packages** — `.pkg.tar.zst` packages for x86_64, aarch64, and armv7h architectures.
- **Report scheduling** — each policy can now have an independent auto-report schedule that automatically saves compliance snapshots on a defined interval.
- `schedule_type` column in `policy_schedules` — supports `scan` and `report` schedule types per policy.
- Schema migration v3 — recreates `policy_schedules` with `UNIQUE(policy_id, schedule_type)` constraint.
- Scheduler now notifies administrators when a scheduled report is saved successfully or fails.

### Fixed
- Policy compliance score — systems with only NA results were incorrectly counted as compliant (100%), now excluded from both numerator and denominator.
- `systems_passed` calculation — now requires at least one PASS result, not just the absence of FAIL results.
- Compliance score returning 100% when all test results are NA — now correctly returns -1 (Not Scanned).
- Compliance score returning 0% for all-NA policies — correctly shows as Not Scanned in dashboard.

### Improved
- Extracted `save_policy_report_logic` as a shared function — used by both the manual save handler and the report scheduler, with `submitter_name` set to the user or `Scheduler` accordingly.
- Schema migration now runs inside a transaction with cleanup of leftover tables from previously failed migrations.

---

## [0.1.6]

### Added

**Server**
- Applicability conditions — tests can now be configured to run only when specific conditions are met (e.g. only run Apache checks if Apache is installed).
- `test_conditions` table to store applicability conditions per test.
- Applicability section in test create and edit forms, and display in test view modal.
- Schema migration system — automatic database upgrades on server startup via `schema_info` table.
- NA count to Highest Risk Assets dashboard table.
- NA badge to policy live report and archived report views.
- NA handling to test detail modal in both live and archived report views.

**Agent**
- Applicability evaluation — agent checks applicability conditions before running a test, sends NA if not applicable.
- Directory content search — File/Content checks against a directory path now search all files in the directory.

### Fixed

**Server**
- Compliance score calculation — NA results were incorrectly included in the denominator, causing scores to appear lower than actual.
- `total_tests` count — now includes NA results so dashboard correctly derives NA count.
- Policy report showing duplicate results for systems in multiple groups — replaced DISTINCT with subquery approach.
- `is_passed` logic — systems with all PASS+NA results now correctly marked as compliant.
- `fail_count` — systems with only NA results no longer counted as failures.

**Agent**
- 100% CPU spike when a File/Content check is run against a directory path — now correctly searches all files in the directory.
- `Unknown string condition: 'None'` errors — empty or None conditions are now skipped gracefully.
- Unsupported platform checks now return NA instead of FAIL.

### Improved
- Multi-condition test logic correctly handles NA — ALL mode: any FAIL→FAIL, all NA→NA, otherwise PASS. ANY mode: any PASS→PASS, all NA→NA, otherwise FAIL.
- Unsupported platform checks return NA instead of FAIL — file/directory owner, group, and permissions on Windows; registry checks on Unix.

---

## [0.1.5]

### Added

**Server**
- Export options to Tests table — PDF, Excel, CSV, print and column visibility.

**Agent**
- macOS preremove script — stops and unloads the service cleanly before uninstall.

### New Platforms
- Linux ARMv7 (armhf) client support.
- macOS universal binary (ARM64 + x86_64) — runs natively on both Apple Silicon and Intel Macs.

### Fixed

**Server**
- Compliance recalculation function — added `tenant_id` filters across all queries, fixed ghost result purge, rewrote policy stats update to be SQLite compatible.
- Missing button titles in server UI.
- Compliance score calculation — NA results were incorrectly included in the denominator.
- `total_tests` count — now excludes NA results to correctly reflect the number of evaluated checks.

### Improved
- Compliance engine refactored to use native Rust functions — replaced external command calls for user/group/port checks.
- Added `group` sub-element for file/directory elements and system group checks — supports `equals`, `contains`, and `regex` conditions.
- Updated Rust toolchain to 1.95.0.

---

## [0.1.4]

### Added

**Server**
- Dynamic settings engine — database-backed `settings` table replacing hardcoded configurations.
- Settings UI — admin interface to configure compliance thresholds and offline detection parameters in real-time.
- Configurable compliance thresholds — SAT, MARGINAL, and UNSAT thresholds fully customizable.
- Offline detection — systems exceeding the configurable inactivity threshold flagged with an Offline badge and greyscale highlighting.
- Context-aware UI — dashboard progress bars and policy status colors update dynamically based on user-defined thresholds.

### New Platforms
- FreeBSD (amd64) — full agent support including native `.pkg` package format, standard `/usr/local` paths, and RC service script.
- Linux PowerPC64LE (ppc64le) agent support.

### Fixed

**Server**
- Self-healing directory structure — prevents crashes if critical application folders (logs, keys, db) are missing or removed.
- Top Failed dashboard table — now excludes systems with a -1 score (unscanned).

**Agent**
- Directory validation logic to ensure agent stability if environment paths are modified or missing.

### Changed
- Deprecated RISC-V support — support may be revisited as the ecosystem matures.

---

## [0.1.3]

### Added

**Server**
- Docker image support — multi-arch images for amd64, arm64, and RISC-V published to Docker Hub (`openscm/scmserver`).
- Test detail modal in live compliance report — click any test name to view description, check procedure, and remediation.
- Test detail modal in archived report view.

### Fixed

**Server**
- -1% display for unscanned policies in dashboard — now shows Not Scanned badge.
- Hourly compliance snapshot firing immediately on startup.
- Redundant compliance recalculation every 60 seconds — removed from loop, only triggered by events and on startup.
- Unused import warnings on Windows.
- `save_to` dead code warning on Windows.
- PDF report rule name overlapping status column — rule names now truncated and wrapped.
- PDF report description column removed from rules table.

**Agent**
- Doc comment `///` → `//` in `config.rs`.
- Maximum tests per system capped at 20 — increased to 500.

---

## [0.1.2]

### Fixed

**Server**
- Default database path on Linux — moved from `/etc/openscm/scm.db` to `/var/lib/openscm/scm.db` following FHS conventions.
- Windows installer using user-specific `%APPDATA%` instead of system-wide `%PROGRAMDATA%`.
- Windows registry key `Tenant_id` → `TenantId` to match server config expectations.
- Windows upgrade file lock error — added graceful `sc stop` before force kill.
- Compliance trend graph tooltip showing unrounded percentages — scores now rounded to 2 decimal places at source.

**Agent**
- Windows installer using user-specific `%APPDATA%` instead of system-wide `%PROGRAMDATA%`.
- Windows registry key `Tenant_id` → `TenantId`.
- Windows upgrade file lock error.

### Improved

**Server**
- Server now runs as dedicated `openscm` system user instead of root.
- Binary path moved to `/usr/bin/scmserver` following FHS conventions.
- systemd service hardening — `NoNewPrivileges`, `ProtectSystem`, `ProtectHome`.
- Restart delay (`RestartSec=5s`) for both Linux and Windows services.
- Log rotation added to Windows service XML.
- Database migration in `postinst` for upgrades from pre-0.1.2.
- Welcome and finish pages, URL/help links, and application icon added to Windows installer.

**Agent**
- Binary path moved to `/usr/bin/scmclient` following FHS conventions.
- Same Windows installer improvements as server.

---

## [0.1.1]

### Added
- Regex condition support (`REGEX`) with multiline file content matching.
- Unscanned systems and policies now display Not Scanned badge instead of 0%.

### Fixed
- Missing `tenant_id` filters across `dashboard.rs` and `systems.rs`.
- Stale compliance results — orphaned results now cleaned up when system groups, policies, or group memberships change.
- `normalize_status` missing NA case — NA results were incorrectly stored as FAIL.
- Compliance trend incorrectly including unscanned systems in average score calculation.
- Compliance history recorded across all tenants instead of per tenant.
- Unscanned systems and policies showing 0% instead of Not Scanned.
- Duplicate failures section displayed in report view.
- Duplicate notifications fetch in `dashboard.rs`.
- Windows upgrade failure — added retry delay when writing agent files to allow the OS to release file locks.

---

## [0.1.0]

First release.
