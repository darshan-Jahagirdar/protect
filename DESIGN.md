# TransFunnel Protect — Design

Status: v1 design, agreed 2026-10-22. Owner: Darshan B Jahagirdar (sole builder and maintainer).
Related docs (Claude Docs): [GTM](https://claude.ai/artifact/CqXX1YdKiuXtyU1PQ83UuM) · [Build plan](https://claude.ai/artifact/M3mtBXQqBcez9xheFecvae) · [Data and compliance](https://claude.ai/artifact/S2wkNVaAxjNRD7bPVi3rgF).
Progress and decisions are logged in [PROGRESS.md](PROGRESS.md). Rules for coding agents are in [AGENTS.md](AGENTS.md).

---

## 1. What Protect is

Protect tells our team within minutes when a newly published security flaw affects a website we manage. It then guides the response from the first alert to the client message.

- **Who uses it:** TransFunnel's internal team only. Clients never log in.
- **What it watches:** about 10 client WordPress sites. Clients are mostly in the US, then India and APAC. There are no EU clients.
- **What it checks:** everything the plugin can see on each site: PHP and its extensions, server libraries, WordPress core, plugins, themes, the database server, the web server and the OS.
- **Why now:** PHP2Shell (CVE-2026-109618 and CVE-2026-109619, 21 Oct 2026) showed that the hard part of an emergency is knowing fast which sites are exposed and what to do.

### v1 workflow

```
Advisory published
  → ingest and normalise
  → match against every site's inventory
  → bucket each match: vulnerable / needs check / safe
  → score priority
  → internal alert (counts only)
  → AI explanation, plus a checklist built from templates
  → team fixes by hand and turns on Cloudflare/WAF protection by hand
  → auto-verify from the site's next report
  → file checks for signs of tampering
  → AI drafts the client message (placeholders; a human fills them in and sends)
  → incident timeline
```

### Milestones

| Milestone | Definition of done |
|---|---|
| **M1: Demo** | The full workflow runs on a local dummy WordPress site with vulnerable PHP. It is triggered by replaying the real PHP2Shell advisory plus one drill plugin advisory. |
| **M2: Production** | Live feeds. All managed sites connected. Hardened hosting in India. Runbooks written. A backup person trained. One real advisory handled end to end. |

### Not in v1 (later)
- One-click Cloudflare actions
- Log-based signals
- A server agent
- A client portal
- Client-facing alerts
- White-label
- Monthly client reports
- Automatic fixes

---

## 2. Principles and hard rules

### The three tests
Every feature and every data field must pass all three:

1. **No commands, no control.** Nothing we build runs a command on a client server or accepts instructions from outside.
2. **No personal data.** We never touch client contacts, visitors, logs, database contents, file contents or credentials.
3. **No new legal document.** If one line in the existing service agreement covers it, it's fine. If it would need a new kind of agreement, it's out.

Ideas that pass all three are judged on usefulness. We are not maximally strict and not maximally lenient.

### Hard rules

| # | Rule |
|---|---|
| R1 | The plugin is **output-only**. It sends reports, and it registers no endpoint, REST route or AJAX handler that accepts external input. The one exception is WordPress's own admin-only, nonce-protected "Report now" button. |
| R2 | The plugin **ignores reply bodies**. From the platform it reads only the HTTP status (success or failure). It never executes, stores or acts on anything sent back. |
| R3 | The plugin **runs no shell commands**. There is no `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, backticks or `eval`. |
| R4 | The plugin's **data list is hard-coded** (section 5.1). There is no setting to send more. Adding a field means updating this doc and the compliance doc. |
| R5 | We **never collect**: client contact names, emails or phones; visitor data or IPs; any logs, including counts; database contents; file contents; passwords, API keys or Cloudflare access. |
| R6 | The database has **no contact fields**. Client names are typed into drafts by a person when sending. |
| R7 | The **AI receives only** advisory text, component names with version numbers, and fixed versions, passed in explicitly. No site URLs, business names or contact details. |
| R8 | The **AI never decides** whether something is vulnerable. The deterministic engine does. AI explains and drafts. |
| R9 | **Internal alerts carry counts only**, for example "3 sites affected, open dashboard". Site lists stay behind the dashboard login. |
| R10 | **People act.** Fixes, Cloudflare changes and client messages are all done by people in v1. |
| R11 | The platform **may view public pages** of client sites, like any visitor (section 4.9). It never logs in, submits forms or probes for weaknesses. |
| R12 | The plugin **may download official reference data** from `api.wordpress.org` and `downloads.wordpress.org` (checksums). It only compares against that data and never executes it. |
| R13 | **Production is hosted in an India region.** |

---

## 3. Architecture

```
 CLIENT SITES (≈10)                    PROTECT PLATFORM (one Python app, India VM)           OUR TEAM
┌──────────────────────┐   signed    ┌──────────────────────────────────────────────┐
│ WordPress            │  report     │  Report API  (/api/v1/enroll, /api/v1/report)│
│  └ Protect Reporter  │ ──HTTPS──▶  │     │ validate · verify signature · dedupe   │
│    plugin (PHP)      │  (hourly +  │     ▼                                        │
│    - inventory       │   on change)│  Inventory  ──▶  Matching engine  ◀── Advisory│
│    - file checks     │             │                 (rules, no AI)       store   │
│    - signs reports   │             │                     │                  ▲      │
└──────────────────────┘             │                     ▼                  │      │      ┌───────────┐
          ▲                          │  Incidents + cases ─▶ Scoring ─▶ Alerts ──────┼────▶ │ Outlook   │
          │ public page view         │        │                  (counts only)       │      │ (+ Teams) │
          │ (headers, TLS) only      │        ▼                                      │      └───────────┘
          └──────────── Observer ◀── │  Checklists (templates) · AI module (explain, │      ┌───────────┐
                                     │  draft) · Timeline · Dashboard ◀──────────────┼──────│ Dashboard │
 PUBLIC SOURCES (download only)      │                                              │      │ (behind   │
 php.net · GitHub php-src GHSA ────▶ │  Feed watchers (scheduled jobs)              │      │  CF Access)│
 CISA KEV · Wordfence · NVD ·        └──────────────────────────────────────────────┘      └───────────┘
 Ubuntu/Debian trackers · wordpress.org
```

Data flows one way from the sites to the platform. Nothing on the platform can reach into a client site, beyond viewing public pages the way any visitor can.

---

## 4. Components

### 4.1 Protect Reporter (WordPress plugin)

| Aspect | Design |
|---|---|
| Slug | `protect-reporter` (working name; final name after the trademark check) |
| Compatibility | PHP 7.4+ and WordPress 5.9+. It must run on the old sites we're trying to protect. Sites on older PHP can't run it, so they go into the inventory by hand and are already flagged as `unsupported_branch`. |
| Dependencies | None. It uses only WordPress core and PHP core. Signing uses `sodium_*`: native ext-sodium, or the `sodium_compat` that ships with WordPress. |
| Settings | Only the platform URL and a one-time enrollment code, on **Settings → Protect Reporter** (admin-only, nonce-checked, via `admin-post.php`). Nothing else is configurable. The URL must be `https://`; plain `http://` is accepted only when `wp_get_environment_type()` is `local` or `development`. |
| Schedule | An hourly WP-Cron event. We recommend a real server cron that calls `wp-cron.php` **over HTTP** (many managed hosts already do this). |
| On change | It also reports right after `upgrader_process_complete` (any core, plugin or theme update). On an admin page load it reports if `PHP_VERSION` differs from the last report. There is a "Report now" button in WP admin. |
| Web SAPI only | It refuses to send if `php_sapi_name() === 'cli'`. A command-line PHP can be a different binary from the one serving the site. The platform also rejects CLI reports. |
| Transparency | A WP admin page shows the exact JSON of the last report sent, plus the time and the result. |
| Uninstall | Deletes its options and keys. It does not phone home. |
| Updates | No self-update from our platform (R1 and R2). We release a zip and the team uploads it by hand, or through an existing site manager. |

**Key handling:** at enrollment the plugin generates an Ed25519 key pair (`sodium_crypto_sign_keypair`). The private key is stored in a non-autoloaded option. The public key is sent once at enrollment. A compromised site can leak only its own key, which affects only its own reports.

### 4.2 Enrollment and the Report API

**Enrollment** is a one-time step for each site:
1. In the dashboard, the team adds the site (business name, URL, host type), and the dashboard shows a **one-time enrollment code**, valid for 24 hours.
2. In the plugin settings, the team enters the platform URL and the code.
3. The plugin generates its key pair and sends `POST /api/v1/enroll` with `{code, site_url, public_key, plugin_version}`.
4. The platform checks that the code is unused and not expired, and that `site_url` matches the registered URL. It then stores the public key. The key ID is `sha256(public_key)[:16]`, which the plugin can work out on its own, so it never needs to read the reply.
5. To rotate keys, generate a new code and re-enroll.

**Report** is `POST /api/v1/report`:

| Header | Value |
|---|---|
| `X-Protect-Key` | key id |
| `X-Protect-Timestamp` | Unix seconds |
| `X-Protect-Nonce` | 16 random bytes, hex |
| `X-Protect-Signature` | base64 Ed25519 signature over `timestamp + "\n" + nonce + "\n" + sha256_hex(body)` |

The platform checks each report in this order. Cheap, unauthenticated checks come first, then the signature, then the rest. A nonce is only recorded once the signature is valid, so nobody can burn a site's nonces.
1. HTTPS (prod only) and the per-IP rate limit.
2. The body is at most 256 KB, read in a stream and cut off past the limit.
3. The signature headers are present and well-formed.
4. The key id is known and the site is active.
5. The timestamp is within ±10 minutes.
6. The signature is valid.
7. The per-key rate limit.
8. The nonce hasn't been seen in the last 15 minutes.
9. The body matches the strict schema (pydantic, no extra fields). Field formats are checked here too: versions look like versions, slugs are `[a-z0-9._-]`, paths are site-relative with no `..`, and there are no control characters.
10. `php.sapi` is not `cli`.

A success returns `204` with no body. The implementation is in `platform/app/api/` and `platform/app/services/`. Until the dashboard screens exist (step 8), sites are added with `python -m app.cli add-site`.

What happens next depends on the result:

| Result | What happens |
|---|---|
| Valid, content unchanged since the last report | Only `last_seen` is updated. |
| Valid, content changed | The report is stored, the inventory is rebuilt, and matching re-runs for that site. |
| Valid but odd (unexpected format, wild version jumps, values outside normal ranges) | The report is stored and the site is flagged **suspicious report** on the dashboard. |
| Invalid | Rejected with a bare 4xx and no detail. The rejection is counted per site in our own logs. |

The API is rate-limited per key and per source IP, and Cloudflare sits in front of it. HTTPS is required. Plain HTTP is accepted only when `PROTECT_ENV=dev`, for the local Docker demo, where the plugin posts to `http://platform:8000`.

### 4.3 Advisory watchers (feeds)

Feeds are scheduled jobs that only download data.

| Source | What we get | Poll | Role |
|---|---|---|---|
| php.net releases JSON (`/releases/?json&version=8`, per branch) | Latest release for each PHP branch | 15 min | PHP core: which version is current |
| php.net news feed (`/feed.atom`) | Security release announcements | 15 min | Early signal |
| GitHub `php/php-src` security advisories (API) | Structured PHP core advisories (GHSA) | 15 min | **Primary** for PHP core |
| CISA KEV JSON | Known-exploited flag | 1 h | Raises priority |
| Wordfence Intelligence vulnerability feed (free, API key; confirm terms) | WordPress core, plugin and theme vulnerabilities with slugs and version ranges | 1 h | **Primary** for WordPress |
| NVD API 2.0 (incremental, `lastModStartDate`) | CVE details, CVSS, CPE | 2 h | Fallback and enrichment only (NVD lags) |
| Ubuntu CVE API and Debian security tracker | Which distro package versions fix each CVE | daily | Distro-patched PHP and libraries |
| OSV.dev (PyPI) | Flaws in Protect's own Python dependencies | daily | Protect watches itself (M2) |

**Review gate:**
- **Structured sources** with machine-readable ranges (GHSA, Wordfence, OSV) are ingested as `confirmed`.
- **Free-text sources** (news feed, NVD without usable ranges) come in as `needs_review`. The dashboard asks a person to confirm the affected ranges and fixed versions. Until then the alert says "possible match, review needed".
- **Manual entry and replay**: the team can enter an advisory by hand, for example from a leak or a vendor email. The demo uses **Replay advisory**, which loads fixtures from `platform/fixtures/advisories/`.
- **Drill advisories** are marked `drill=true`. Every view, alert and draft they produce is labelled `[DRILL]`.

Each feed run is recorded in `feed_runs`. A feed that fails three runs in a row raises an internal alert.

### 4.4 Component catalogue (the naming table)

The same software is named differently everywhere. Every component gets one standard key, and each source's name maps to that key. This table is the core of the "intelligence": if it's wrong, matches are missed silently.

| Key pattern | Examples | Comes from |
|---|---|---|
| `php` | `php` | `PHP_VERSION` |
| `php-ext:<name>` | `php-ext:imagick`, `php-ext:redis` | `get_loaded_extensions()` + `phpversion($ext)` |
| `lib:<name>` | `lib:openssl`, `lib:curl`, `lib:libxml2`, `lib:pcre2`, `lib:icu`, `lib:imagemagick` | PHP constants and functions (section 5.1) |
| `wordpress` | `wordpress` | `get_bloginfo('version')` |
| `wp-plugin:<slug>` | `wp-plugin:contact-form-7` | `get_plugins()` |
| `wp-theme:<slug>` | `wp-theme:astra` | `wp_get_themes()` |
| `db:<engine>` | `db:mysql`, `db:mariadb` | `$wpdb->db_server_info()` |
| `server:<name>` | `server:apache`, `server:nginx`, `server:litespeed` | `SERVER_SOFTWARE` |
| `os:<id>` | `os:ubuntu`, `os:debian`, `os:almalinux`, `os:cloudlinux` | `/etc/os-release` |

`component_aliases` maps outside names to these keys: NVD CPE strings, Wordfence slugs, Ubuntu/Debian package names (`php8.3`, `openssl`), and so on. Adding a source means adding its aliases. A source name with no known alias is logged as **unmapped**, so we notice it instead of silently missing it.

### 4.5 Matching engine (rules, no AI)

Matching is deterministic, pure Python, and heavily table-tested. For each site component and each confirmed advisory that affects that component, it returns one of three buckets:

| Bucket | Meaning |
|---|---|
| **vulnerable** | The version is inside an affected range and no rule says it's patched. |
| **needs_check** | We can't tell from the version alone. A person must confirm with the host or by other means. |
| **safe** | The version is fixed or outside the affected ranges, and no case is created. |

**Version parsing:**
- **PHP:** parse `PHP_VERSION` as `MAJOR.MINOR.RELEASE` plus `extra`. Never feed the raw string to a semver library: `8.1.2-1ubuntu2.20` would sort as a pre-release, *below* 8.1.2.
- **WordPress core and plugins:** use loose numeric comparison of dot and dash parts. Anything unparseable goes to `needs_check`, never `safe`.
- **Ranges** follow the OSV style: a list of `{introduced, fixed}` or `{introduced, last_affected}` events per branch.

**Distro and host rules for PHP and libraries:**

| Situation | Detected by | Result if the upstream number is below the fix |
|---|---|---|
| Upstream build, or a third-party repo that tracks upstream releases (for example Sury) | `extra` empty | **vulnerable** (the number is accurate) |
| Ubuntu build (`-1ubuntuX.Y`) | `extra` matches the Ubuntu pattern | Compare the package version with Ubuntu's fixed package version. **vulnerable** or **safe**; **needs_check** if Ubuntu data is missing |
| Debian build (`-N+debXuY`, `~deb`) | `extra` | Same, using the Debian tracker |
| RHEL family (RHEL, AlmaLinux, Rocky, CloudLinux) with no suffix | os-release `ID`/`ID_LIKE` | **needs_check**: fixes may be backported without a version change |
| Branch past end of life with no official fix (for example PHP ≤ 8.1 for PHP2Shell) | Advisory has no fix for that branch | **vulnerable**, marked `unsupported_branch`. The fix is "upgrade the branch" (or confirm the host's backport, then mark it by hand) |

**OS-provided components:** `php-ext:*`, `lib:*`, `db:*` and `server:*` are installed and patched by the OS or host, which often backports fixes without changing the version number. If one of these is inside an affected range, it is **needs_check**, never vulnerable or safe on its own. A version outside the range is **safe**.

**Distro fix data** is stored in `advisory_affects.distro_fixes` as `{distro: {os_version_id: {package: value}}}`, for example `{"ubuntu": {"22.04": {"php8.1": "8.1.2-1ubuntu2.21"}}}`. The value is one of:
- the first fixed package version, compared with dpkg's rules
- `"not-affected"`
- `"unfixed"`

Missing data means **needs_check**. The implementation is in `platform/app/engine/` (`versions.py`, `matcher.py`, `catalogue.py`).

The host type (managed WordPress, cPanel, VPS) changes **who fixes it and how** (the checklist template). It does not change whether the site is vulnerable.

When an advisory's ranges change, or a site's inventory changes, matching re-runs for the affected pairs.

### 4.6 Priority scoring

The score is simple, explainable, and always shown with its reasons.

| Factor | Points |
|---|---|
| CVSS ≥ 9.0 / 7.0–8.9 / 4.0–6.9 / < 4.0 | 40 / 25 / 10 / 3 |
| Known exploited (CISA KEV, or the team ticks "exploited" from credible reports) | +30 |
| Remote and unauthenticated (CVSS `AV:N` and `PR:N`) | +10 |
| Site risk tag `ecommerce` | +10 |
| Site risk tag `personal_data` | +10 |
| Component inactive (deactivated plugin or theme; its files may still be reachable) | −10 |
| Shielded (WAF rule confirmed active) | −5 |

| Priority | Score |
|---|---|
| P1 | ≥ 70 |
| P2 | 50–69 |
| P3 | 30–49 |
| P4 | < 30 |

`needs_check` gets the same score as `vulnerable` but is labelled differently. For example, PHP2Shell scores 40 + 30 + 10 = **80, which is P1**, on every SAPI: mod_php carries the most risk, but PHP-FPM is still critical.

### 4.7 Incidents and cases

- An **incident** is one real-world event. It can have several advisories: PHP2Shell is one incident with two CVEs. The client gets **one** message per incident.
- A **case** is one site within one incident.
- A new confirmed advisory that matches at least one site opens an incident, or joins an open one if its aliases overlap. The team can merge or split incidents by hand.

Each case tracks four things separately:

| Field | Values |
|---|---|
| `exposure` | `vulnerable`, `needs_check`, `fix_claimed`, `verified`, `not_affected`, `false_positive`, `accepted_risk` |
| `shielded` | yes or no, plus a note (for example "Cloudflare managed rule confirmed") |
| `compromise` | `none`, `suspected`, `confirmed` |
| `client_notice` | `not_needed`, `drafted`, `approved`, `sent` (sent is marked by a person) |

```
vulnerable ──(team: "fixed")──▶ fix_claimed ──(next report shows fixed version)──▶ verified
     │                                │
     │                                └─(report still old after 2h)──▶ flag "fix not visible"
needs_check ──(team records host confirmation + note)──▶ verified (manual, with evidence note)
any ──(team, with reason)──▶ false_positive | accepted_risk | not_affected
```

An incident **closes** when every case is `verified`, `not_affected`, `false_positive` or `accepted_risk`, and every needed client notice is marked `sent`.

### 4.8 Alerts

| Channel | Use | How |
|---|---|---|
| **Email (Outlook / Microsoft 365)**, primary | All alerts | Production: Microsoft Graph `sendMail` with an app registration (application `Mail.Send`, restricted to one sender mailbox by an application access policy). We avoid SMTP basic auth, which Exchange Online plans to disable by default at the end of Dec 2026. Demo: SMTP to Mailpit. |
| **Microsoft Teams**, optional | Mirror of P1 and P2 to a team channel | A Teams **Workflows** webhook (the old Office 365 connectors are retired) |

**Rules:**
- P1 and P2: alert immediately. P3 and P4: daily digest email.
- Content is counts only (R9): `"[Protect] P1 — 3 sites affected by PHP2Shell (CVE-2026-109618, CVE-2026-109619). Open dashboard: <link>"`. Advisory names and CVEs are public, so they're fine. Site names and URLs are never included.
- The link points to `/incidents/<random id>`. It needs a dashboard login.
- **Acknowledge** in the dashboard ("I'm on it"). If there's no ack within 15 minutes, the alert is re-sent to the backup person, and to Teams if configured. While no backup person is set (the current state), the re-alert goes to the primary again with "[UNACKNOWLEDGED]" in the subject.
- One alert per incident, plus one update when the number of affected sites goes up. No repeat alerts for the same case.

### 4.9 Observer (public page view)

This is a second opinion that a hacked plugin can't fake.

- **What:** one `GET /` per site, with a user agent of `TransFunnel-Protect-Observer/1.0`, following up to 3 redirects. It reads response headers (`Server`, `X-Powered-By`, `cf-ray`, `server: cloudflare`) and the TLS certificate expiry. No crawling, no logins, no form submits, no probing paths.
- **When:** daily, and every 30 minutes for sites in an open P1 or P2 incident.
- **Gives us:**
  - Whether the site is behind Cloudflare. This feeds the shield step.
  - The PHP version, if the header shows it. If it **disagrees** with the plugin's report, the case is flagged **"report and public view disagree"**.
  - TLS expiry, as a small extra.
- **Legal:** covered by one line added to the existing authorization clause ("we may view your public web pages"). No new document is needed.
- **Demo:** in the demo, the observer uses the site's internal Docker URL (`http://wp-vuln`), because `127.0.0.1:8081` isn't reachable from inside the platform container.

### 4.10 AI module

The AI layer is swappable behind one interface: `ai.generate(task, inputs) -> AIResult`. The provider is chosen in config.

| Setting | Default |
|---|---|
| Provider and model | Google Gemini, `gemini-4-argon` (paid API tier; trial credits) |
| `incident_summary` task | thinking level **medium** (fast in an emergency) |
| `client_draft` task | thinking level **high** (quality matters; nobody is waiting) |
| Fallback providers | `anthropic`, `openai`, `fake` (tests, offline demo) |

- **Input allowlist (R7):** the input builder accepts only advisory text, `{component name, version}` pairs, and fixed versions, and rejects anything else. Site URLs and business names are never passed.
- **Caching:** one summary per incident, reused across all its cases. It is regenerated only when the incident's advisories change.
- **Drafts use placeholders** that a person fills in: `{{CLIENT_NAME}}`, `{{SITE_NAME}}`, `{{SENDER_NAME}}`, `{{FIX_TIME}}`. The tool never sends anything.
- **Untrusted output:** advisory text may contain prompt-injection text. AI output is shown as escaped Markdown, never decides status (R8), and every draft needs human approval.
- **Record keeping:** each result stores the provider, model, prompt version and time.
- **Compliance:** Google is listed as a subprocessor. Check whether the model can be served from an India region.

### 4.11 Checklists (templates, not AI)

Fix steps come from reviewed templates, never from AI. They live in `platform/app/checklists/templates/<incident_kind>/<host_type>.yaml`.

- **Incident kinds:** `php-core`, `lib`, `wp-core`, `wp-plugin`, `wp-theme`, `suspicious-file`.
- **Host types:**
  - `managed-wp` **first**, since our known sites are on managed WordPress hosts.
  - `cpanel` and `vps` as generic templates, to refine once hosting is confirmed.
- **Variables** are filled in deterministically: current version, fixed version for this branch, CVE IDs, and whether the site is behind Cloudflare (from the observer).
- **Item types:** `manual` (a person ticks it, and the tick is logged) or `auto` (ticked by the system, for example "report shows fixed version").

**Example: `php-core / managed-wp`**
1. Check the host's status page or announcement for its patch status.
2. In the host panel, confirm the site's PHP version. If the host lets you choose, switch to `{{fixed_version}}` or newer on this branch.
3. If it's not patched within 4 hours, open a host support ticket and log the ticket reference.
4. Confirm edge protection is active: the Cloudflare managed rules (if `behind_cloudflare`) or the host's own WAF. **Not** "Under Attack" mode, which is a DDoS challenge.
5. If the site is on Cloudflare, confirm the origin accepts traffic only from Cloudflare, or note that it can't.
6. *(auto)* The next report shows the fixed version. Use "Report now" to speed it up.
7. Review the file-check results for this site.
8. Approve and send the client notice.

### 4.12 File checks (run on the site, results only)

| Check | How | Notes |
|---|---|---|
| WordPress core integrity | Compare MD5s with `api.wordpress.org/core/checksums/1.0/?version=X&locale=<get_locale()>` | Reports mismatched and unexpected files in `wp-admin/` and `wp-includes/` as site-relative paths |
| Plugin integrity (wordpress.org plugins) | `downloads.wordpress.org/plugin-checksums/<slug>/<version>.json` | Premium or private plugins: `unverifiable` |
| PHP in uploads | Any `*.php`/`*.phtml`/`*.phar` under `wp-content/uploads` | Known harmless placeholders are allowed (`index.php` that matches known "Silence is golden" hashes, hashed locally) |
| Unknown must-use plugins | Files in `wp-content/mu-plugins` that aren't on the team's allowlist for that site | Allowlist set in the dashboard |
| Hiding spots | `ini_get('auto_prepend_file')` / `auto_append_file`: is it set, and is it inside the site root (site-relative path) or `outside_site_root`? Also any `.user.ini` files under the site root | We never send paths outside the site root; they can contain server usernames |
| Recently changed PHP (low weight) | PHP files whose mtime changed in the last 7 days outside known update events, up to 50 paths | Noisy, and attackers can fake mtimes. A hint, not proof |

- **Batching:** scans run in small batches across cron runs, with a time budget of 10 seconds per run. A cursor is stored, so cheap shared hosts never hit their time limits.
- **Wording:** results are always "no warning signs found", never "clean". A compromised site can lie (section 6).
- **Demo:** plant a harmless `wp-content/uploads/test.php` (it contains only a comment) and show it being flagged.

### 4.13 Dashboard

- **Pages:**
  - Overview: open incidents, stale sites, suspicious reports, feed health
  - Sites: inventory, last report, observer results, enrollment
  - Incident: summary, cases table, timeline
  - Case: checklist, status buttons, file checks, drafts
  - Advisories: including the review queue, replay and manual entry
  - Settings: users, alert recipients, mu-plugin allowlists
- **Tech:** FastAPI, Jinja2 with **autoescape on**, and HTMX. No SPA.
- **Access in production:** the dashboard sits behind **Cloudflare Access**, using Microsoft Entra ID (Microsoft 365) single sign-on, which enforces MFA. The app validates the `Cf-Access-Jwt-Assertion` token and maps emails to roles. Only `/api/v1/*` bypasses Access.
  - Fallback if Cloudflare Access isn't possible: app login with TOTP 2FA.
- **Access in the demo:** a local dev login, enabled only when `PROTECT_ENV=dev`.
- **Roles:** `admin` (users, settings), `responder` (acts on cases), `viewer` (read only).
- **Browser hardening:** strict CSP (`default-src 'self'`; no inline scripts; HTMX served locally), CSRF tokens, `SameSite=Strict` cookies, and sessions that expire after 12 hours.
- **Untrusted data:** everything from sites, advisories and the AI is shown as text. Nothing from them is ever passed through `|safe`.

### 4.14 Timeline and metrics

Every state change is an `event`, with the actor (a user or `system`) and the time. The incident timeline shows:

`advisory published → ingested → matched → alerted → acknowledged → shielded → fix claimed → verified → client notified`

**Headline metric:** time from advisory published to every affected site verified and its client notified.

Other metrics:
- Time to acknowledge
- Share of sites with a report in the last 3 hours
- Number of `needs_check` cases still open

### 4.15 Monitoring the monitor

| Check | Rule |
|---|---|
| **Heartbeat** | The scheduler pings healthchecks.io (free) every 5 minutes. If the pings stop, healthchecks.io emails the team: Protect is down. |
| **Stale sites** | A site is `stale` after 3 hours with no report. At 24 hours it's included in the daily digest. In an open P1 or P2 incident, stale affected sites are flagged prominently. |
| **Feed failures** | Three failed runs in a row raise an internal alert. |
| **Self-watch (M2)** | Protect's own Python dependencies are checked against OSV daily, and the host OS is listed as a pseudo-site. |

---

## 5. Data

### 5.1 Report payload (schema v1)

All fields are versions, settings or site-relative paths. Nothing personal.

```json
{
  "schema": 1,
  "plugin_version": "0.1.0",
  "generated_at": "2026-10-22T10:00:00Z",
  "site_url": "https://example.com",
  "php": {
    "version": "8.3.30", "major": 8, "minor": 3, "release": 30, "extra": "",
    "sapi": "apache2handler",
    "extensions": [{"name": "imagick", "version": "3.7.0"}],
    "ini": {
      "session.upload_progress.enabled": "1",
      "memory_limit": "256M",
      "opcache.enable": "1",
      "expose_php": "1"
    }
  },
  "libs": {
    "openssl": "OpenSSL 3.0.13 30 Jan 2024",
    "curl": "8.5.0", "curl_ssl": "OpenSSL/3.0.13",
    "libxml2": "2.9.14", "pcre2": "10.42", "icu": "74.2", "imagemagick": "7.1.1-21"
  },
  "wordpress": { "version": "6.6.2", "multisite": false, "locale": "en_US" },
  "plugins": [{"slug": "contact-form-7", "version": "5.9.8", "active": true, "name": "Contact Form 7"}],
  "mu_plugins": [{"file": "wp-content/mu-plugins/host-tools.php", "name": "Host Tools", "version": ""}],
  "themes": [{"slug": "astra", "version": "4.8.1", "active": true}],
  "db": { "engine": "mariadb", "version": "10.11.6" },
  "server": { "software": "Apache/2.4.58 (Ubuntu)" },
  "os": { "id": "ubuntu", "id_like": "debian", "version_id": "24.04", "pretty_name": "Ubuntu 24.04.1 LTS" },
  "checks": {
    "core":   {"status": "ok", "modified": [], "unexpected": []},
    "plugins": [{"slug": "contact-form-7", "status": "ok", "modified": []}],
    "uploads_php": ["wp-content/uploads/test.php"],
    "mu_plugins_present": ["wp-content/mu-plugins/host-tools.php"],
    "user_ini": [],
    "auto_prepend": {"set": false, "location": null},
    "recent_php_changes": [],
    "scan": {"complete": true, "finished_at": "2026-10-22T09:58:00Z"}
  }
}
```

- `name` fields are for display only. They're attacker-controllable on a hacked site, so they're always escaped and never used for matching.
- Any field the plugin can't read (for example `/etc/os-release` blocked by `open_basedir`) is sent as `null`, never guessed.

### 5.2 Database tables

The production database is SQLite (WAL mode), accessed through SQLAlchemy 2 with Alembic migrations. Switching to PostgreSQL later is a config change.

| Table | Key columns |
|---|---|
| `sites` | id, business_name, url, host_type (`managed-wp`/`cpanel`/`vps`/`unknown`), host_name, server_group, risk_tags (json), mu_plugin_allowlist (json), status (`pending`/`active`/`removed`), key_id, public_key, enrolled_at, last_report_at, last_report_id, suspicious (bool), created_at |
| `enrollment_codes` | code_hash, site_id, expires_at, used_at |
| `reports` | id, site_id, received_at, content_hash, schema, plugin_version, payload (json), flags (json) |
| `site_components` | site_id, component_key, version_raw, version_parsed (json), distro, active, first_seen, last_seen (the current inventory, rebuilt from the latest report) |
| `nonces` | key_id, nonce, seen_at (pruned after 15 min) |
| `observations` | id, site_id, at, http_status, server_header, powered_by, behind_cloudflare, tls_expires_at, error |
| `advisories` | id, aliases (json: CVE, GHSA, Wordfence id…), source, source_url, title, summary_text, cvss_score, cvss_vector, kev, exploited, published_at, review_status (`confirmed`/`needs_review`/`rejected`), drill, created_at |
| `advisory_affects` | advisory_id, component_key, ranges (json, OSV-style), fixed_versions (json), distro_fixes (json) |
| `component_aliases` | component_key, alias_type (`cpe`/`wordfence`/`wporg`/`ubuntu_pkg`/`debian_pkg`), alias_value |
| `incidents` | id (random), title, kind, priority, status (`open`/`monitoring`/`closed`), drill, created_at, closed_at |
| `incident_advisories` | incident_id, advisory_id |
| `cases` | id, incident_id, site_id, component_key, exposure, shielded, shield_note, compromise, client_notice, priority, score, score_reasons (json), owner_user_id, created_at, updated_at |
| `checklist_items` | case_id, template_key, item_key, kind (`manual`/`auto`), done_by, done_at, note |
| `events` | id, incident_id, case_id, actor_user_id (null = system), type, at, note, data (json) |
| `ai_results` | id, incident_id, case_id, task, provider, model, prompt_version, content, created_at |
| `drafts` | id, incident_id, case_id, content, ai_result_id, approved_by, approved_at, sent_marked_by, sent_at |
| `alerts` | id, incident_id, channel, recipients_group, sent_at, acked_by, acked_at, escalated_at |
| `feed_runs` | id, source, started_at, finished_at, status, items_new, error |
| `users` | id, email, display_name, role, totp_secret_enc (fallback only), created_at, disabled_at (our team only) |
| `audit_log` | id, at, actor_user_id, action, target, data (json) (logins, user and setting changes) |

There are no contact fields anywhere (R6).

### 5.3 Retention

| Data | Kept |
|---|---|
| Reports | 12 months (the latest report per site is always kept) |
| Observations | 90 days |
| Nonces | 15 minutes |
| Incidents, cases, events, drafts | 12 months after the incident closes |
| Platform logs (our own systems) | 180 days, in India (CERT-In) |
| Everything for a client | Deleted when the contract ends ("Remove site" in the dashboard) |

---

## 6. Security design

The goal: a full breach of Protect exposes a list of sites and their versions, and gives **no access** to any client site.

| Threat | Mitigation |
|---|---|
| A hacked client site sends a script inside a plugin name, which then runs in our dashboard | Jinja autoescape, a strict CSP, field-format validation, and a "suspicious report" flag |
| A hacked site lies ("patched, no warning signs") | The observer cross-checks; stale and odd-behaviour flags; wording is "no warning signs found", never "clean" |
| Report forgery or replay | Ed25519 signatures per site, a ±10 min timestamp window, nonces |
| Theft of the platform database | It holds only public keys (no shared secrets); disk encryption; the dashboard is behind Access; minimal data |
| A compromised platform server tries to attack client sites | There is no path: the plugin accepts no input and ignores reply bodies (R1, R2) |
| A compromised platform server sends fake alerts or drafts | Humans approve every draft and verify fixes; no automatic actions in v1 |
| Stolen dashboard session | Cloudflare Access with Entra MFA, short sessions, CSRF tokens, `SameSite=Strict` |
| Alert email read by a third party | Alerts carry counts only |
| Prompt injection in advisory text | AI never decides status; output is escaped; a human approves |
| Flooding the report API | Cloudflare in front, rate limits, a 256 KB body cap |
| Supply chain, platform side | Dependencies pinned (`uv.lock`) and checked against OSV daily (M2) |
| Supply chain, plugin side | No third-party libraries; releases built from this repo only, with a published SHA-256 checksum; installed by hand |
| The vulnerable demo site gets hacked | It is bound to `127.0.0.1` only, with no tunnels. The public test site runs patched PHP only |

---

## 7. Compliance mapping

No new legal documents are needed. These existing docs need updating:

| Doc | Change |
|---|---|
| Data and compliance: data inventory | Add PHP extensions and versions, server library versions, the selected PHP settings, DB server version, mu-plugin file names, hiding-spot checks, and public page observations |
| Service agreement: authorization clause | Add "we may view your public web pages" and "the plugin compares files against official WordPress checksums" |
| Subprocessor list | Google (Gemini API), Microsoft (email and Teams alerts), Cloudflare (Access, and in front of the API), the hosting provider, healthchecks.io (receives pings only) |
| GTM | Drop or redefine the "Monitor" tier (client-facing alerts would need contact data). Replace the "zero successful compromises" metric. Source or remove the unverified PHP2Shell timing claims |
| Data and compliance: design rules | Make "never collect logs" read "never collect **client** logs". Protect's own logs are kept for 180 days under CERT-In |

---

## 8. Environments and deployment

### Demo (local, M1)

`docker/compose.yaml` runs these services:

| Service | What | Bound to |
|---|---|---|
| `wp-vuln` | WordPress on `php:8.3.30-apache` (mod_php, older than the 8.3.36 fix). Custom Dockerfile; confirm the tag exists at build time | `127.0.0.1:8081` **only** |
| `wp-db` | MariaDB | internal network |
| `wp-cron` | Small curl loop that calls `http://wp-vuln/wp-cron.php` every minute (cron over HTTP, as in production) | internal |
| `platform` | Protect platform (`PROTECT_ENV=dev`) | `127.0.0.1:8000` |
| `mailpit` | Catches alert emails | `127.0.0.1:8025` |

- **Patch step:** switch `wp-vuln` to `php:8.3.36-apache` and rebuild. The next report shows the fixed version, and the case becomes **verified**.
- **Never** expose `wp-vuln` beyond localhost, and never put real exploit code in the repo.

### Public test site (before M2)

A real, empty WordPress site (nothing for sale) on **fully patched** PHP, hosted on a managed WordPress host. It's used to test real hosting, cron, Cloudflare, plugin feeds and email. The full alarm flow is tested with **drill advisories** (`[DRILL]`).

### Production (M2)

- **Server:** one small VM in an India region with an encrypted disk. First choice is Oracle Cloud Always Free (Mumbai or Hyderabad), because it costs nothing. Oracle can reclaim free VMs it considers idle, so the heartbeat (§4.15) doubles as the warning if that happens. Fallback: a small paid VM such as DigitalOcean Bangalore or AWS Mumbai, around $6–10 a month.
- **Process:** Caddy (TLS) in front of one `uvicorn` process run by systemd.
  - Use **one worker only**. The scheduler runs inside the app, and more workers would run every job more than once.
- **Cloudflare:** in front of the domain. Access covers everything except `/api/v1/*`.
- **Backups:** SQLite backed up continuously with Litestream to an India-region object storage bucket. Restores are tested monthly.
- **Secrets:** in a `.env` readable only by the service user. `.env.example` is committed; `.env` never is.

---

## 9. Repository layout

```
Protect/
├── AGENTS.md            rules for coding agents (CLAUDE.md imports it)
├── CLAUDE.md
├── DESIGN.md            this file
├── PROGRESS.md          status board, decision log, work log
├── docker/
│   ├── compose.yaml
│   ├── wp-vuln/Dockerfile
│   └── wp-cron/
├── plugin/
│   └── protect-reporter/
│       ├── protect-reporter.php
│       ├── includes/    (inventory, checks, signer, sender)
│       ├── admin/       (settings, transparency page)
│       └── uninstall.php
└── platform/
    ├── pyproject.toml   (uv)
    ├── app/
    │   ├── main.py
    │   ├── api/         (enroll, report)
    │   ├── dashboard/   (routes, templates, static)
    │   ├── engine/      (versions.py, matcher.py, scoring.py, catalogue.py)
    │   ├── feeds/
    │   ├── alerts/
    │   ├── observer/
    │   ├── ai/
    │   ├── checklists/templates/
    │   ├── models.py, db.py, settings.py, security.py
    ├── migrations/
    ├── fixtures/advisories/   (php2shell.json, drill-plugin.json)
    └── tests/
```

**Platform stack:** Python 3.12, FastAPI, Jinja2, HTMX, SQLAlchemy 2 + Alembic, pydantic v2, APScheduler, httpx, PyNaCl (Ed25519), google-genai (behind `ai/`), and pytest.

---

## 10. Testing

- **Engine (most important):** table-driven tests for version parsing and matching. They cover upstream, Sury, Ubuntu and Debian suffixes, RHEL with no suffix, unsupported branches, unparseable plugin versions, inactive components, and PHP2Shell itself across every branch.
- **API:** good signature, bad signature, a replay, a stale timestamp, an oversized body, extra fields, a CLI SAPI, and a script payload in a plugin name (it must end up escaped in the HTML).
- **Plugin:** a PHP unit test for payload building (with no network), plus a check that the code contains none of the banned functions (R3).
- **AI:** the `fake` provider in tests. A test that the input builder rejects any field outside the allowlist.
- **End to end (demo):** replay PHP2Shell, check that an alert reaches Mailpit, patch the container, and check that the case becomes `verified`.

---

## 11. Demo script (about 10 minutes)

1. The dashboard shows the dummy site on PHP 8.3.30 (mod_php), reporting in.
2. **Replay PHP2Shell.** A P1 incident opens and the alert email arrives (Mailpit in the demo, Outlook in a rehearsal on the test site).
3. Open the incident: one affected site, score 80 with its reasons, the AI summary, and the `managed-wp` checklist.
4. Show the shield step (Cloudflare managed rules) and tick it by hand, with a note.
5. Patch the container to 8.3.36 and press "Report now". The case turns **verified** on its own.
6. File checks flag the planted `uploads/test.php`.
7. Show the AI client draft with placeholders and approve it. Mark it sent, and show the full timeline.
8. *(Optional)* replay the drill plugin advisory to show that the tool covers more than PHP.

During the demo, say what's real and what's simulated. Simulated: the advisory arriving (real PHP2Shell data, replayed) and the Cloudflare step (manual in v1). Everything else is real.

---

## 12. Open questions and assumptions

Answers as of 2026-10-22. The live status is in [PROGRESS.md](PROGRESS.md).

| # | Question | Answer or working assumption |
|---|---|---|
| Q1 | Which hosts are the ~10 sites on? | Probably WP Engine. The `managed-wp` templates are tuned for WP Engine first, with generic cPanel and VPS templates for the rest |
| Q2 | Any non-WordPress PHP sites? | Unknown. v1 covers WordPress only |
| Q3 | Which sites are behind Cloudflare? | Unknown. The observer detects it |
| Q4 | Is the TransFunnel domain on Cloudflare (needed for Access)? | Unknown; ask IT. If not, put a separate dashboard domain on Cloudflare's free plan, or fall back to TOTP login |
| Q5 | Who can create the Graph app registration and the sender mailbox? | The IT team, asked before M2 |
| Q6 | Who is the backup person for alerts? | No one yet. Escalation re-alerts the primary and mirrors to Teams if configured. Name a backup before founding clients |
| Q7 | Which production VM provider? | Free if possible: Oracle Cloud Always Free (Mumbai or Hyderabad). Oracle can reclaim idle free VMs. Fallback: a small paid VM in India |
| Q8 | Do the Gemini trial credits cover `gemini-4-argon`, and can it run in an India region? | The user will check. The swappable AI module limits the risk |
| Q9 | Wordfence Intelligence feed terms for internal commercial use | To be read when building feeds. Fallback: WPScan API or Patchstack |
| Q10 | Final product and plugin name | "Protect" for now, plugin slug `protect-reporter`. Trademark check before client rollout |
