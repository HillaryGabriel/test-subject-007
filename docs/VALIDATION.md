# Test Subject 007 - complete-project validation

## This delivery

`Test-Subject-007-Complete-Project.zip` is the complete source application prepared from the full repository restoration package. It is NOT the changes-only archive. No older application files are required.

Application modules, test modules, dependency declarations, launchers, and GitHub workflows are unchanged from that complete DFIR source. The documentation now leads with new-repository setup. `.gitignore` explicitly permits the reviewed `docs/hash-intelligence-template.csv` source template; investigation CSV exports remain ignored.

No remote repository, branch, workflow run, or release was created or changed from this environment.

## Checks performed for this package

- Full isolated test suite under Linux/Xvfb, Python 3.13.5: **230 tests; 228 passed; 2 skipped; 0 failures; 0 errors**. The runner completed in 39.6 seconds. See [the complete local log](LOCAL_TEST_OUTPUT.txt).
- The two skips are installed Volatility engine discovery and invalid-image engine smoke tests. Volatility is not installed in this test environment. The suite was run without `--require-all` locally so skips remain explicitly reported; the included CI workflow retains `--require-all`.
- All 92 source-manifest entries are present exactly once: 88 non-hidden files and four hidden configuration files. No extra generated runtime directories, client captures, original client reports, or binary evidence are included.
- Python source syntax and Linux shell syntax passed.
- Updated README and GitHub-guide relative links and Markdown code fences were checked.
- Git ignore checks confirmed that the header-only intelligence template is trackable while `.venv`, memory dumps, and generated report CSVs remain ignored.
- ZIP CRC, safe member paths, and freshly extracted file-byte comparisons were checked against every manifest entry. These checks confirm packaging consistency, not forensic correctness.

## Remaining acceptance

This package has not been run natively on Windows in this environment, and its new GitHub CI run has not been observed. A new repository must run the complete Windows/Ubuntu matrix for Python 3.11 and 3.12. Earlier green commits from another repository do not validate this new upload.

No genuine memory image, actual memory PE recovery, genuine EVTX parser acceptance, or clean internet-based dependency installation was validated during this repackaging. Local tests exercise synthetic evidence, real Tk widgets, hashing of local fixture bytes, XML handling, and subprocess behavior. PDF/report tests in the suite do not amount to a new visual review of a real case report.

Passing automated checks is not a clean-host verdict. Preserve forensic evidence separately, use compatible symbols, compare selected app results with equivalent CLI output on an authorized reference capture, and verify event time/source semantics and recovered-file provenance before operational conclusions. Original-file and memory-reconstructed hashes remain distinct.

## Source versus installed dependencies

This is a source distribution, not a standalone Windows EXE, an AppImage, an offline dependency bundle, or a hosted forensic service. Launchers install required packages from the user's approved package sources. No virtual environment is shipped. Keep the source upload copy separate from the installed working copy.
