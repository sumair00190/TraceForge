# TraceForge release checklist

## Verified locally — 2026-10-26

- [x] 85 unit tests passed.
- [x] Synthetic scan and three training captures processed.
- [x] Fresh root commit uses noreply author and committer identities.
- [x] Targeted source search found no tested personal-email, token or private-key patterns; not a comprehensive secret audit.
- [x] Captures, reports and Python caches excluded from the launch commit.
- [x] LICENSE, NOTICE and screenshot assets retained.

## Pending launch work

- [ ] Keep the original repository private because historical commits/PRs contain personal email metadata.
- [ ] Push this prepared history to a fresh private repository.
- [ ] Verify pushed commit/tag identities and fresh CI.
- [ ] Confirm attribution and dependency/asset redistribution permissions.
- [ ] Review screenshot content and metadata.
- [ ] Check remaining docs for obsolete development references.
- [ ] Finalize release notes and create the release tag.
- [ ] Change visibility when the owner authorizes publication.
- [ ] Verify public README, screenshots, license and release downloads.
- [ ] Publish the LinkedIn announcement when requested.

Old tags, releases and PRs are not part of this fresh history.
Historical email metadata has not been removed from the original repo.
