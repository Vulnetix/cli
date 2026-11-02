# Action fixture

What the `actions-e2e` job in `.github/workflows/test.yml` runs the actions against: a
vulnerable `package.json`, a SAST pattern (`src/app.py`), a fake secret (`src/settings.env`,
not a real credential) and, in `vulnetix-config/`, a `.vulnetix` folder that mixes Platform IaC
documents with a SARIF file and a CycloneDX file, plus `ai-firewall.yaml`. The job copies
the fixture to a scratch directory and renames `vulnetix-config/` to `.vulnetix/` there, so no
`.vulnetix/` directory is committed.
