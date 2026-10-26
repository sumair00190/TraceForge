# TraceForge Apache-2.0 release checklist

This checklist describes **preparation**, not authorization to publish. The repository must remain private until the owner explicitly approves changing visibility.

## Legal and contribution readiness

- [x] Include the full Apache License 2.0 in `LICENSE`.
- [x] Declare `Apache-2.0` and license file in Python package metadata.
- [x] Add contributor guidelines, community standards and a security reporting policy.
- [ ] Confirm the legal copyright owner/attribution language and any third-party notices before public release.
- [ ] Audit dependencies, committed history, screenshot metadata and any third-party code/assets for redistribution rights. Initial screening found no obvious sensitive filenames across current branch heads or common API-key patterns in current source; this is not a guarantee.
- [x] **Current branch/tag email check (2026-10-23):** At main commit `9064127`, all 21 reachable commits use GitHub noreply author/committer emails. Both annotated tags (`v1.0`, `v1.1.0`) and their reachable commit histories also use noreply emails. This supersedes the earlier warning about 19 Gmail-authored commits.
- [ ] Review historical PR references/diffs, cached content and any other published artifacts before launch. The branch/tag check does not establish removal from every GitHub surface or from other repositories.
- [x] Add and verify both cropped synthetic-only screenshots in `docs/images/` and the README gallery (merged PR #12).
- [ ] Decide whether to enable GitHub private vulnerability reporting, Discussions and community templates.

## Engineering and evidence

- [x] No outstanding PRs; latest GitHub main CI passed Python 3.10/3.13 tests and TShark capture smoke checks.
- [x] Confirm both CLI entry points and complete 85-test suite on Kali with v1.1.0 (user-provided terminal evidence).
- [x] Verify synthetic baseline PCAP, scan PCAPNG/CAP, batch dashboard and evidence using GitHub Actions; the v1.1.0 Kali scan PCAPNG also passed. Full large-capture stress testing remains out of scope.
- [x] Verify GitHub Actions wheel metadata states Apache-2.0 and includes LICENSE/NOTICE; wheel build also succeeded on Kali.
- [ ] Review captures and generated reports for secrets, tokens and sensitive data before publication.
- [x] State tested versions, missing coverage, false-positive limitations and observed synthetic results in README and validation docs. No claim of comprehensive detection accuracy.
- [x] Create annotated `v1.1.0` tag (currently pointing to commit `ccf9e4a`), update CHANGELOG and prepare draft release notes. The separate v1.1 GitHub Release remains unpublished; original `v1.0` is unchanged.

## Launch when explicitly authorized

- [x] Confirm name TraceForge, © 2026 sumair00190 attribution, and review synthetic overview/evidence screenshots following [SCREENSHOTS.md](SCREENSHOTS.md).
- [ ] Change GitHub visibility to public **only after separate confirmation**.
- [ ] Verify what a logged-out viewer sees (README, LICENSE, releases, Actions, examples).
- [ ] Publish the prepared GitHub release and then the dedicated LinkedIn post on the agreed schedule.

**Important:** Adding `LICENSE` to a later commit does not change the files inside the existing `v1.0` tag. Do not describe that original tag as if it already includes these new files. Apache-2.0 permits commercial redistribution subject to its conditions; releasing the source does not guarantee employment, contributors or sales.
