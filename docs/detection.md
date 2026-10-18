# Detection and severity

Scoring is additive and capped at 100. Every event stores its exact reasons and points.
Path tests are case-insensitive for security classification and inspect both the old
and new path on rename. No file contents are interpreted or executed.
Executable permission checks inspect both before and after records, including deleted
files and files whose execute bits were removed.

| Rule | Points | Trigger |
| --- | --- | --- |
| File change | 10 | Every detected event |
| Script | 20 | `.py`, `.ps1`, `.sh`, `.bat`, `.cmd`, `.js`, `.vbs` |
| Executable | 25 | `.exe`, `.dll`, `.so`, `.dylib`, `.com`, `.msi`, or any POSIX execute bit |
| SSH | 45 | `.ssh` component or `authorized_keys`, `sshd_config`, `known_hosts` filename |
| Startup | 35 | `startup`, `autostart`, `systemd`, `cron.d`, `init.d` component |
| Web directory | 20 | `www`, `wwwroot`, `htdocs`, `public_html` component |
| Permission | 15 | Before/after permission modes differ |
| Mass changes | 40 | At least configured threshold of events within the incident window |
| Database integrity violation | 90 | Explicitly acknowledged database/config tampering |

| Score | Severity |
| --- | --- |
| 0–24 | low |
| 25–49 | medium |
| 50–79 | high |
| 80–100 | critical |

Incident grouping reuses the most recent open incident whose last event falls within
the configured window, default 60 seconds. Otherwise it creates a new incident. Its
score is the maximum event score. This temporal grouping is a heuristic; it does not
claim unrelated changes share an attacker. Incidents currently retain `open` status.

Mass changes default to 20 events in 60 seconds, not 20 distinct files. At the threshold,
earlier events within the sliding window are rescored so a burst spread across multiple
scans is visible. Subsequent report reads reflect the updated incident scores. Already
delivered notifications are not resent just because historical event scores changed.

Content changes take precedence over metadata-only changes for the event kind; full
before/after records and permission scoring preserve simultaneous metadata evidence.
A rename can also carry changed content in its before/after hashes. Renames use unique
device/inode identities, followed by unique hash/size matches. Hardlinks, inode reuse,
case-only renames, and delete/create operations with identical content can be ambiguous.

These are review heuristics, not signatures for malicious behavior. A harmless script
deployment can legitimately produce high severity; an unrecognized configuration path
may score low. Baseline approval is a human trust decision, never a scoring consequence.
