# Third-party notices

Test Subject 007 is an independent Python interface and is not an official
Volatility Foundation product. Application source is supplied under the MIT
License in `LICENSE`. No claim is made that this license replaces a dependency's
license, changes trademark rights, or authorizes use of a third party's branding.
Review the application name and license before organizational publication.

No dependency source, third-party wheel, symbol database, memory sample or font
file is bundled in this source archive. Installation resolves dependencies from
the user's configured Python package index. Those components retain their own
licenses and notices. Review the installed distributions before redistribution,
especially when making an executable installer.

## Main engine

- Project: Volatility 3, Volatility Foundation and contributors.
- Pinned application dependency: `volatility3==2.28.2`.
- Upstream: https://github.com/volatilityfoundation/volatility3
- License: Volatility Software License; read the release's actual license file.
- Release license source:
  https://github.com/volatilityfoundation/volatility3/blob/v2.28.2/LICENSE.txt

## Other runtime components

Python and Tcl/Tk are provided by the analyst's Python/OS installation and retain
their upstream license terms. SQLite is accessed through Python's standard
library. The optional `analysis` extra installs `yara-python`, `capstone` and
`pycryptodome`; these and their transitive/native components retain their own
upstream terms. Their names here identify technical dependencies, not endorsements.

- Python: https://www.python.org/
- Tcl/Tk: https://www.tcl.tk/
- YARA Python: https://github.com/VirusTotal/yara-python
- Capstone: https://github.com/capstone-engine/capstone
- PyCryptodome: https://github.com/Legrandin/pycryptodome

## PDF generation

ReportLab is an installed runtime dependency for PDF generation. It and its
transitive dependencies retain their own license terms. No ReportLab wheel or
font file is bundled. The PDF renderer uses available operating-system fonts
when present and can embed font subsets in generated reports. Review your
font and redistribution permissions before distributing reports.

- ReportLab: https://www.reportlab.com/

## Reproducibility and supply chain

The main engine is pinned, but optional and transitive dependency versions are
bounded rather than fully hash-locked. Record a workstation's resolved environment
with `python -m pip freeze`. For controlled deployments, create and approve a
platform-specific dependency lock and wheelhouse from a trusted package index,
scan it, and retain package checksums. Do not assume that a source-code checksum
alone authenticates dependencies downloaded later.

## Supplemental evidence parsing

The runtime uses defusedxml for restricted XML parsing. The analysis extra includes python-evtx for analyst-supplied EVTX files. Their dependencies and licenses remain separate; no source or wheel is bundled.

- defusedxml: https://github.com/tiran/defusedxml
- python-evtx: https://github.com/williballenthin/python-evtx
