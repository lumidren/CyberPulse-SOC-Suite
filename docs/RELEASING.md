# Release Process

CyberPulse follows [Semantic Versioning](https://semver.org):

* **MAJOR**: incompatible changes, including any change to *automation
  behaviour* that could surprise an operator (for example a new default
  policy mode, or a guard that now blocks something it allowed before).
* **MINOR**: new features that keep existing behaviour (new rules,
  endpoints, integrations).
* **PATCH**: bug fixes and documentation.

## Steps

1. Update `CHANGELOG.md`: move items under a new `## [X.Y.Z] - YYYY-MM-DD`
   heading. Automation-behaviour changes go under **Changed (automation
   behaviour)** so operators can review them before upgrading.
2. Set the same version in `pyproject.toml` and `server.py` (`__version__`).
3. Check: `python scripts/release_notes.py --check X.Y.Z` (also enforced by
   `tests/test_release.py` for the latest CHANGELOG version).
4. Commit, then tag and push the tag:
   ```bash
   git tag -a vX.Y.Z -m "CyberPulse X.Y.Z"
   git push origin vX.Y.Z
   ```
5. `.github/workflows/release.yml` re-runs the tests on the tagged commit,
   verifies the tag matches the project version, and publishes a GitHub
   release whose notes are that version's CHANGELOG section.

Never move or re-push an existing tag; publish a new patch version instead.
