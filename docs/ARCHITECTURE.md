# Application architecture

The existing case, audit, subprocess runner, streaming log viewer, option preflight and CSV/SQLite evidence index are retained. Original output is immutable by convention, not physically immutable storage. Reports are derived artifacts.

New/updated analysis modules:

- triage_rules.py: semantic command/source-field classification and conservative path/behavior checks.
- process_review.py: process identities, captured paths, compatible parent context and ambiguity safeguards.
- chronology.py: raw timestamp preservation, explicit UTC/PHT conversions and typed memory chronology.
- supplemental.py: case-owned import copies, SHA-256, audited manifests and integrity checks.
- eventlogs.py: analyst-supplied EVTX/XML parsing and provider/channel-specific authentication/session semantics; no RAM carving.
- binaries.py: acquired and recovered file-byte hashes, representation-specific intelligence matches and basic structure limits.
- assessment.py: explicit human disposition and recorded evidence-state fingerprint.
- evidence_ui.py: investigator actions for paths, byte collection, time sources and manual assessment.
- findings.py / summary.py: grouped leads, separate context, suppression ledger and quality/coverage reporting.
- report_details.py: compact PDF details and complete structured sidecars; HTML retains full finding text.

The GUI never executes recovered samples or automatically uploads memory/files/hashes to third parties. Volatility symbol downloads remain separately controlled by the saved symbol policy. Dependencies are installed through the user's approved package source. Windows expected-location checks use captured NtSystemRoot, not the analyst's filesystem. Matching digest text in memory is not a computed file hash.

Supplemental imports copy the provided files into the case. Source, records and manifest hashes are checked on report rebuild. These controls do not make a local mutable case an immutable evidence vault. Independent acquisition/custody records remain required.

External log evidence is distinguished from analyst-supplied memory-recovered log files. Event hosts are not silently merged and event IDs are interpreted only with the expected provider/channel. Account names and source IPs do not identify the human operator or prove authorization.
