# Validation - evidence-led DFIR update

## Completed locally

The final application suite ran through scripts/run_tests.py in isolated test processes under Linux/Xvfb, Python 3.13:

**230 tests; 228 passed; 2 skipped; 0 failures; 0 errors.**

This includes the prior Windows resolved-path assertion fixes and 53 new tests covering field-aware suppression, benign interpreter context, specific suspicious commands, system-path baselines, missing OS root, ambiguous PIDs, original-vs-reconstructed hashes, local intelligence provenance/conflicts, imported event semantics, UTC/PHT conversions, XML entity rejection, bounded imports, tampering, report sidecars, stale analyst conclusions, and real Evidence lab widgets.

A synthetic fixture with 113 PATHEXT rows creates zero actionable script findings while preserving 113 source-linked suppression entries and all original rows. Normal Java, service display names and event-log handles are not treated as malicious execution. This is a regression fixture, NOT reanalysis of the 010LP memory image.

Synthetic reports were generated through the application exporter, rendered and visually checked. The example is 8 pages and explicitly marked SYNTHETIC DEMO. Actual Tk views were captured at 1500x960 and the 1160x760 minimum. No image mock-ups, real binary samples, client data or font files are shipped in the source archive.

## Limits

The two skipped checks are installed-engine discovery and an invalid-image engine smoke test. Volatility could not be installed from the available package sources in this build environment. Native Windows execution, a new genuine-memory investigation, actual memory PE recovery and parsing of a genuine EVTX file were not performed here. XML event import and synthetic recovered-artifact hashing were exercised. The EVTX import uses python-evtx's record/XML API and still requires target-workstation acceptance testing.

No private GitHub repository was changed and no remote CI result for this update is claimed. The existing workflow keeps --require-all: required checks must not be skipped in GitHub Actions. Earlier green runs apply to the earlier source, not this update.

## Required acceptance on your workstation

1. Review the source diff and run the complete Windows/Ubuntu matrix on the new commit.
2. Install the merged source in a new environment with analysis extras; retain resolved package versions.
3. Compare a known authorized capture's selected CLI plugin output against preserved app output with identical engine, arguments and symbols.
4. Validate executable recovery against known source bytes. Do not expect reconstructed PE hashes to equal original-file hashes.
5. Compare imported session events with the original provider/channel/host/record IDs and UTC timestamps in EVTX/XML.
6. Exercise live logging, cancellation, export, report paths and reopening an existing case. Verify file and case integrity independently.
7. Review heuristic false positives against approved tools. An automated pass or absence of findings is not a clean-host verdict.

Full local output is in LOCAL_TEST_OUTPUT.txt. No tests were disabled to obtain a passing result.
