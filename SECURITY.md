# Security and evidence handling

## Intended environment

Use this application only for authorized analysis of previously acquired memory
images. Run it as a normal analyst account in an isolated investigation workstation
or VM. The parser and its dependencies process attacker-controlled data; a plugin
subprocess is an isolation boundary for responsiveness, not a security sandbox.
Keep the analysis host patched and restrict its network and filesystem access.

Memory and recovered files can contain credentials, personal information, keys and
malicious code. Store cases and captures on access-controlled encrypted storage.
The application does not encrypt its case files. Do not submit private images or
outputs to public repositories, CI, issue trackers or online analysis services.

## Evidence integrity

The application hashes a selected regular file using SHA-256, records its file
metadata, references it in place, and checks for a change before analysis. Full
post-batch hash verification is enabled by default. Relinking requires the same
SHA-256. This is not acquisition, a hardware write blocker, an immutable evidence
store, or protection from another process modifying a file. Reads may update
filesystem access-time metadata. Use a verified forensic working copy or an
appropriately read-only evidence source and follow your organization's custody
procedure. Protect the original acquisition and its independent hash record.

A local attacker with write access can replace case files and recompute the
unkeyed audit chain. The chain detects accidental edits or partial tampering, not
all malicious rewriting. Export records to an independently protected system when
stronger custody assurance is required. Output hashes recorded in run metadata are
not automatically revalidated on every result view or report export.

Case locks prevent supported local concurrent application writers. Network
filesystem locking semantics can differ; use a local case workspace. Protect both
the capture and case directory from untrusted local users and symlink replacement.

## Plugins and extracted artifacts

All plugins loaded from the installed Volatility package are exposed. Only install
trusted Python packages, symbol files, custom plugins and YARA rules. Some plugins
may recover passwords or other highly sensitive artifacts. Use their results only
within authorized investigation scope.

Extracted files are saved per run and are never deliberately executed by the UI.
Opening an artifact directory launches the operating system's file manager; it is
not a malware detonation sandbox. Disable unsafe previews and do not execute or
open suspicious extracted material on a normal workstation. Maintain separate
malware analysis procedures.

User inputs are passed in an argument array without shell evaluation. This does
not make a third-party plugin safe or validate the forensic meaning of its output.
Canceled, partial, failed and timed-out results are explicitly distinguished from
successful results. A plugin's successful exit is not proof of a clean system.

## Network and symbols

Offline mode is the default. Disabling it permits Volatility's symbol mechanisms
to make outbound connections; environment proxy settings may also apply. Although
the UI has no memory upload service, operating-system sync clients, installed
plugins or dependency behavior must still be controlled by the analyst. Obtain
symbols from trusted official sources and ensure matching kernel identity.

The app ignores a user's ambient Volatility `vol.json` defaults so the generated
command is reproducible. Inspect the saved command, engine configuration and log
for every important run. The system Python environment and trusted installed code
remain within the trust boundary.

## Exports and publication

Analyst CSV exports escape spreadsheet-formula prefixes. Raw CSV is retained
unchanged for provenance and should not be opened directly in spreadsheet programs
without an appropriate safe import. HTML text is escaped and active content is
restricted by a Content-Security-Policy. PDF, JSON, HTML, logs and source paths may still
contain sensitive data; review before sharing.

There is no automatic repository publishing step. Review all browser-uploaded
files, the commit diff, screenshots and repository history before publishing.
File extensions and `.gitignore` do not detect all secrets or prevent an unsafe
manual browser upload. Private GitHub
repositories are not a substitute for an approved evidence storage system.

## Reporting a security defect

Before publishing a repository, configure a private vulnerability-reporting contact
or GitHub private vulnerability reporting. No monitored security email address is
bundled here. Do not post captures, credentials, client names or exploit-sensitive
artifacts to a public issue. Provide a minimal non-sensitive reproducer and the
application, engine and dependency versions.

## Operational readiness

Read `docs/TESTING.md`. This source implementation needs real-engine and known-image
acceptance on the intended Windows/Linux workstations before operational reliance.
