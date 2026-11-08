# Investigation goals and necessary scope

Choose an investigation question, then review its actual plugin plan. Cards select installed plugins; they do not guarantee artifact recovery. Windows and Linux plans are different. Additional required options still go through preflight.

| Card | Best use | Necessary scope and limits |
|---|---|---|
| Incident triage | Establish the memory baseline | Image/OS information, process lists/scans/trees, commands, network objects, modules and memory candidates. Not full disk or historical incident reconstruction. |
| Remote access & RDP | Review remote-tooling and available remote-access times | Process/service/session context, network objects and Created times, selected registry settings. Import workstation-specific EVTX/XML in Evidence lab for authentication/logon/disconnect events. IT authorization must be corroborated separately. |
| Network evidence | Investigate observed endpoints and process context | NetScan/NetStat or supported Linux socket output, ownership, state, port, timestamp and references. Do not treat connections as unique logons or ports as verified protocols. Optional search terms are local matching, not reputation. |
| Process integrity | Review masquerading, suspicious paths and candidate code | Process identities, captured paths, compatible parent context, modules, VAD/memory candidates and selected cross-view plugins. Windows location checks require captured OS root. Acquire bytes in Evidence lab for hashes. |
| Suspicious execution | Investigate concrete interpreter abuse | Actual command fields, interpreter primary tokens, configured autostarts and file context. Encoded/download-execute/remote-content/exposed-script patterns are leads. Ordinary Java/PowerShell, PATHEXT, documentation and log filenames are not actionable by themselves. |
| Persistence | Review possible launch mechanisms | Startup executable context, services, Run/RunOnce keys and available task/history artifacts. Configuration is not execution. Disk-only persistence may be absent from memory. |
| Activity timeline | Establish time relationships within evidence limits | Process lifetime timestamps and available console/history data; network times and imported events when available. No capture/report time substituted for missing event time. |
| Kernel integrity | Review kernel-module discrepancies | Modules, drivers, callbacks and selected cross-view sources. Legitimate instrumentation/acquisition problems may resemble tampering. No name-only rootkit verdict. |
| Full evidence survey | A broad curated collection for an unclear incident | Combined process, memory, network, file, handle, service, registry and kernel sources. Specialist rule/source/offset inputs, credentials and bulk extraction remain deliberate advanced actions. |

Exact plugin candidates, aliases, Windows/Linux separation and explicit registry queries are defined in `test_subject_007/profiles.py`. Availability depends on the installed Volatility catalog. Use **Review plan** to see what will actually run. Unsupported/missing tasks remain in coverage reporting.

The new Suspicious execution card replaces the former broad Java/VBS/script use case. Existing case metadata keeps its original plan label for historical provenance; it is not rewritten to claim that a new scope was run.
