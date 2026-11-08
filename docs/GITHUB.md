# Test Subject 007 - publish a new repository

This is the COMPLETE application, not a patch. No older application folder or changes-only archive is needed. The source has 92 files: 88 visible files and four hidden configuration files. `PUBLIC-FILES.txt` lists every intended source file.

GitHub stores the source and runs automated checks. Memory analysis runs locally on your Windows or Linux desktop. This is not a website deployment, a GitHub Pages application, or a public memory-upload service.

## 1. Extract a clean upload copy

Extract `Test-Subject-007-Complete-Project.zip` into an empty folder. Open the inner `test-subject-007` directory. `README.md`, `pyproject.toml`, `scripts`, `tests`, and `test_subject_007` must be directly inside it.

Use a clean extraction for uploading. Install and run the application in a separate working copy. Never upload `.venv`, `.setup`, captures, case folders, collected executables, real reports, credentials, or client data. `.gitignore` is not a browser-upload filter.

Preserve your old repository and forensic case data. A new repository does not require deleting either.

## 2. Create the repository in your signed-in GitHub browser

Click **+ > New repository**. Use:

| Field | Selection |
|---|---|
| Owner | Your account |
| Repository name | `test-subject-007-dfir`, or another unused name |
| Description | Local memory-forensics workbench powered by Volatility 3. |
| Visibility | Private initially |
| Add README | Off |
| Add .gitignore | None |
| Choose a license | None |

The project already includes the README, ignore file, and license. The new repository name does not change the application name or Python module. Click **Create repository**.

## 3. Upload the complete visible contents

On the empty repository page, choose **uploading an existing file**. Otherwise use **Add file > Upload files** at the repository root.

Open the extracted `test-subject-007` folder on your computer. Select its VISIBLE contents and drag them into GitHub. This uploads 88 files, including files inside folders. Do not drag the enclosing `test-subject-007` folder or the ZIP itself.

Correct pending paths:

```text
README.md
pyproject.toml
PUBLIC-FILES.txt
RUN-LINUX.sh
scripts/run_tests.py
test_subject_007/__init__.py
test_subject_007/engine.py
tests/test_dfir.py
```

Incorrect pending paths:

```text
test-subject-007/README.md
github-update/test_subject_007/engine.py
```

Complete the upload and review all selected paths. Commit to the default branch of this NEW empty repository with the message:

```text
Add complete Test Subject 007 DFIR application
```

Do not install or run the application in the upload copy. Do not delete any files before uploading.

## 4. Add the four hidden files through GitHub's editor

Because dragging hidden files failed in your browser earlier, use **Add file > Create new file** instead. Return to the repository ROOT before each creation.

For each row below, enter the exact path in the filename field, open the matching local file in a text editor, copy ALL its contents, paste into GitHub, and commit. Do not paste Markdown code fences around the content and do not add `.txt` to the filename.

| Order | Exact GitHub path | Matching local file |
|---|---|---|
| 1 | `.gitignore` | `test-subject-007/.gitignore` |
| 2 | `.gitattributes` | `test-subject-007/.gitattributes` |
| 3 | `.github/workflows/build.yml` | `test-subject-007/.github/workflows/build.yml` |
| 4 - last | `.github/workflows/ci.yml` | `test-subject-007/.github/workflows/ci.yml` |

On your Linux file manager, enable Show Hidden Files (normally Ctrl+H) to locate these local files. On GitHub, typing `/` in the name creates the directory path. Do not remove the dots from `.github`, `.gitignore`, or `.gitattributes`.

Create `ci.yml` LAST, after all source and other configuration files are present. It is the automatic validation workflow; adding it last avoids running checks against a partially uploaded project. `build.yml` is manually triggered.

The directory listing may show `.github/workflows` as a compact path. Open it and verify that both YAML files exist.

## 5. Verify the source layout

Your repository root should contain:

```text
.github/
  workflows/
    ci.yml
    build.yml
docs/
scripts/
test_subject_007/
tests/
.gitattributes
.gitignore
INSTALL-LINUX.sh
INSTALL-WINDOWS.cmd
LICENSE
MANIFEST.in
PUBLIC-FILES.txt
README.md
RUN-LINUX.sh
RUN-TEST-SUBJECT-007.sh
RUN-WINDOWS.cmd
SECURITY.md
START-LINUX.sh
START-WINDOWS.cmd
THIRD_PARTY_NOTICES.md
pyproject.toml
requirements-analysis.txt
requirements.txt
```

This is a structural checklist; `PUBLIC-FILES.txt` is the complete list. Every path in that manifest must exist. The current package has no file requiring a large-file upload.

## 6. Review GitHub Actions

Open **Actions > Cross-platform validation** and inspect the NEWEST run for the commit that added `ci.yml`.

The workflow targets:

| Runner | Python |
|---|---|
| Ubuntu | 3.11 |
| Ubuntu | 3.12 |
| Windows | 3.11 |
| Windows | 3.12 |

All four configurations should finish successfully before treating the source as validated by this matrix. The workflow retains `--require-all`, so missing GUI or engine checks cannot silently pass as skipped tests.

When a job fails, open that job and expand the first failed step. Save the actual traceback or installation error, not only `Process completed with exit code 1`. Do not delete files, disable tests, add `continue-on-error`, or remove `--require-all` to make it green.

A manual start is available under **Cross-platform validation > Run workflow** when the workflow is on the default branch. Select the branch with the completed upload. Re-running an old failed run checks its original commit, not a newer repair.

A green workflow is automated validation, not proof that every capture can be analyzed or that every forensic finding is correct. Validate an authorized reference capture separately.

## 7. Install a separate working copy

After checking the repository, use **Code > Download ZIP** and extract to a NEW working folder. Open a terminal in the folder containing `pyproject.toml`.

### Kali, Ubuntu, or Debian graphical desktop

Install prerequisites:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip python3-tk
```

Install and launch as your normal desktop user:

```bash
bash RUN-LINUX.sh
```

For Windows symbol retrieval ONLY when your investigation policy permits it:

```bash
bash RUN-LINUX.sh --online-symbols
```

Subsequent launches:

```bash
bash RUN-LINUX.sh
```

First setup installs Python dependencies from your configured package sources. The installer log is `.setup/install.log`. Do not continue past installation errors. Do not copy an old `.venv` or run the app with sudo.

### Windows desktop

Use supported 64-bit Python with Tcl/Tk. Extract the source into a new folder and double-click:

```text
RUN-WINDOWS.cmd
```

For approved online-symbol access, open PowerShell in that folder:

```powershell
.\RUN-WINDOWS.cmd --online-symbols
```

Stop and inspect installation errors before analyzing evidence.

## 8. Use the application

**Add memory > choose an investigation > review the plan > run > review findings > export.** Choose the operating system of the captured computer, not the analyst workstation. Supply compatible symbols. Store cases and reports outside the source tree.

Existing cases can be opened separately. Use **Rebuild findings** to apply the current rules to saved output; it does not rerun Volatility, manufacture missing evidence, or rewrite old PDFs. Optional event import and executable collection remain deliberate actions.

## Future changes

Create a review branch, upload the intended update over matching paths, review tests and the diff, then merge. A changes-only archive requires an intact base project. Never delete source folders as the first step of an update. See [Safe updates](UPDATE-GITHUB.md).

## Official references

- [Create a repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/creating-a-new-repository)
- [Upload existing files](https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository)
- [Create files and directory paths](https://docs.github.com/en/repositories/working-with-files/managing-files/creating-new-files)
- [Read workflow logs](https://docs.github.com/en/actions/how-tos/monitor-workflows/use-workflow-run-logs)
- [Run workflows manually](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)
