# Safely update Test Subject 007

For a NEW repository, use [the new-repository guide](GITHUB.md). This page applies to later updates.

## Preserve the working project

Do not delete the repository or application folders before an update. Preserve captures, cases, acquired files, and reports separately. Keep an installed working copy separate from a clean upload copy.

A changes-only archive requires the intact complete source. After accidental deletion or an incomplete upload, restore a COMPLETE project on a review branch; do not use a patch as a replacement project.

## Apply a coherent update

1. Open the Code tab. Create a review branch from the current main branch.
2. From the repository root, use Add file > Upload files. Upload the intended source contents with their existing relative paths. Do not add an enclosing archive folder.
3. Keep all unchanged required files. Include dependency files and PUBLIC-FILES.txt when the update supplies replacements.
4. Commit the coherent update. Review its Files changed view and newest Cross-platform validation run.
5. Open a pull request with main as the base and the review branch as the comparison. Merge after reviewing the checks. Check the resulting main-branch run as well.

Do not force-push, turn off tests, or weaken --require-all to bypass a failure. A new error needs the first failed step's actual output. Re-running an older workflow tests its original commit, not the updated files.

## Install the reviewed source

Download the merged source and use a new working folder and virtual environment. Existing case data can be reopened from its separate storage location. Rebuild findings and create a new report; do not overwrite historical reports or original plugin outputs. Additional evidence collection and event imports require explicit analyst actions.

GitHub stores the application source; the desktop app and memory analysis run locally.

## Optional command-line publisher

The included scripts/publish_github.py is an alternative for an already authenticated GitHub CLI session. Browser and CLI authentication are separate. Its source allowlist is PUBLIC-FILES.txt; it does not publish evidence or force-push. Review its target and file list before confirming PUBLISH.

Official references: [file uploads](https://docs.github.com/en/repositories/working-with-files/managing-files/adding-a-file-to-a-repository), [pull requests](https://docs.github.com/en/pull-requests/get-started/pull-request-quickstart).
