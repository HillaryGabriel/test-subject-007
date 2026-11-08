# Test Subject 007 - evidence-led DFIR update

## What changed

Actionable findings are separated from background context and data-quality limitations. Original plugin rows are never removed. A suppression ledger explains why environment settings, service display names and event-log/library references were not promoted into script-execution findings. An interpreter's presence is not a malware verdict.

The nine investigation cards have no Targeted, Focused, Broader or Extensive badges. Their scopes are Incident triage, Remote access & RDP, Network evidence, Process integrity, Suspicious execution, Persistence, Activity timeline, Kernel integrity and Full evidence survey. Specialist checkboxes and option preflight remain available under Advanced plugins.

Concrete command patterns generate source-linked leads: encoded PowerShell, combined download/execution tokens, MSHTA remote/inline content, exposed-location WScript/CScript/JAR invocation, selected interpreter autostarts and compatible Office-parent interpreter chains. These heuristics are incomplete; successful execution, content and intent are not automatically established.

Process-integrity rules compare a small explicit set of Windows system-executable names against the captured NtSystemRoot. Directory checks are withheld when the captured root is unavailable; selected look-alike names remain reviewable. Device paths are compared without resolving them against the analyst's filesystem. Unknown applications in AppData are not blanket malware findings. Ambiguous/reused PIDs do not support confident location or hash attribution.

Memory candidates are grouped per process. Mapped jump destinations retain same-PID module references and signature caveats. Fully mapped candidate groups are context, not automatically benign. Unresolved candidates remain review items. No automatic rootkit verdict is made.

## Evidence lab

**Processes & paths** shows captured identities, parent context, paths and byte-collection status. Select an unambiguous Windows process and choose **Collect selected PE** to run the installed pslist extraction for that PID. Confirm the action. It does not execute the recovered file or silently bulk-dump all memory. An exited/unavailable process may yield no executable. Linux original-file acquisition works, but this one-click PE action is Windows-capture specific.

**Files & SHA-256** supports an acquired-file import and source-attributed hash intelligence. SHA-256 is calculated from actual copied or extracted bytes and verified again when the report is rebuilt. PID/path associations on supplied files are explicitly analyst-supplied. A filename, PID, address, symbol identifier or whole-image hash is never substituted for a file hash. No binary bytes means the hash is unavailable.

Representations are distinct:
- `acquired_file`: the analyst-supplied file bytes, not necessarily unchanged since capture.
- `memory_reconstructed_pe`: PE bytes reconstructed by Volatility; not necessarily the original file.
- `memory_artifact`: extracted memory/cache bytes; original-file equivalence unverified.

Basic PE/ELF header checks are not completeness or authenticity checks. Partial bytes can have a hash, but that hash describes only those bytes. Authenticode/signature verification is NOT implemented; status is Not verified, not Unsigned. No external reputation lookup or sample upload occurs.

Hash-intelligence CSV columns: `sha256,label,source,reference,representation`. Labels: `malicious`, `suspicious`, `known_good`. Source and reference are mandatory. Matches require the computed digest AND matching representation. A known-bad match is a claim by the supplied intelligence source, not independent malware analysis or proof of active infection. Conflicting entries are visible. Known-good matching does not suppress suspicious behavior or path findings. No threat hashes are shipped by default.

**Timeline & logons** preserves original time strings and displays normalized UTC and PHT (UTC+08:00). Network Created, process CreateTime and imported event TimeCreated are not interchangeable. Missing or timezone-unknown times stay unavailable. The app does not infer authorization, human identity or session duration from a port or PID.

Import analyst-supplied EVTX or XML Events exports and explicitly choose external versus memory-recovered provenance. Relevant events include Security 4624/4625/4634/4647/4776/4778/4779, RemoteConnectionManager 1149 and LocalSessionManager 21-25, with provider/channel verification. Event 4624 Type 3 is not Type 10; NTLM validation is not desktop logon. Hosts are retained separately. Duplicate imports of the same record are deduplicated without dropping import references. Different source files/hosts are not automatically merged.

EVTX parsing requires the `analysis` extra. XML uses defusedxml with DTD/entities blocked. Imports copy and hash the source, record parser errors and limits, and retain source provenance. The import limit is 512 MiB and 200,000 records; partial coverage is explicit. This is NOT a raw-RAM EVTX carver, full EVTX checksum validator or an automatic reconstruction of missing log history. An export from a domain controller must not be treated as a workstation session log.

**Analyst assessment** requires a rationale and supporting evidence references. A human-confirmed disposition is explicitly separate from automated results and becomes stale after recorded evidence changes. Case records are local and mutable; the hash chain is not an immutable evidence vault or digital signature.

## Reporting and older cases

Open an existing preserved case and select Findings > Rebuild findings, or Evidence lab > Rebuild from saved evidence. This applies the new interpretation to saved plugin output; it does not rerun Volatility, change the original memory image, or create missing timestamps. Older cached findings are not presented as current until rebuilt. Export a NEW report bundle; existing PDFs remain unchanged.

The report leads with actionable items and quality caveats. Background context and suppression counts are separate. Network-object creation times, imported session events, process chronology, original fields, UTC/PHT, actual binary hashes and their representations are visible. PDF detail is bounded (30 findings, 25 event records, 20 binary entries); the PDF says so. Full details and provenance remain in HTML/CSV/JSON, with all original plugin output retained.

Exports include report.pdf, report.html, results.csv, findings.csv/json, network-context.csv, remote-access.csv, script-references.csv, suppression-ledger.csv, process-inventory.csv, executable-hashes.csv, event-timeline.csv, memory-timeline.csv, quality-flags.csv, malfind-regions.csv, observable-exclusions.csv, search-matches.csv and planning/coverage sidecars. Source files may be sensitive; store reports outside the GitHub source folder.

## Important limits

No exhaustive malware detection, proof of a clean host, automatic binary execution, online reputation lookup, Authenticode validation or raw-memory event carving is claimed. An acquisition, symbol, plugin or record-quality problem remains a coverage limitation. Evidence absence in one plugin is not evidence of absence from RAM/disk/history. Follow your organization's evidence-preservation and forensic-handling procedures.

## Primary technical references

- Volatility PE reconstruction: https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/pslist.html
- Volatility network objects: https://volatility3.readthedocs.io/en/stable/_modules/volatility3/plugins/windows/netscan.html
- Windows logon types: https://learn.microsoft.com/windows/security/threat-protection/auditing/basic-audit-logon-events
- NTLM credential validation: https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776
- EVTX parser: https://github.com/williballenthin/python-evtx
- Safe XML parsing: https://github.com/tiran/defusedxml
