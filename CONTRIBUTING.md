# Contributing

## Rule requirements

Validation runs on pull requests and on pushes to `main`, via
[`.github/workflows/validate.yml`](.github/workflows/validate.yml).

### Sigma

- Generate a fresh UUID per rule: `python3 -c "import uuid; print(uuid.uuid4())"`
- Required metadata: `title`, `id`, `status`, `description`, `author`, `date`,
  `logsource`, `detection`, `falsepositives`, `level`
- Map to [ATT&CK](https://attack.mitre.org/) via `tags` where applicable
- `falsepositives` must list real scenarios, not "unknown"
- Rules must convert cleanly to every backend their platform targets — CI
  enforces this. Windows rules go to Splunk, Elasticsearch and Microsoft XDR;
  AWS and Okta rules to Splunk and Elasticsearch
- File naming: `<category>_<platform>_<behavior>.yml`

### YARA

- Rule names use `PascalCase` with underscores: `Webshell_PHP_Generic_Eval`
- Required `meta`: `description`, `author`, `date`, `reference`, `severity`
- Bound scans with `filesize` as the first condition — it short-circuits before
  string matching
- Prefer behavioral logic (input source plus execution sink) over static
  signatures that break on trivial modification

## Testing

Every YARA rule needs both a true positive and a false positive sample. CI fails
if a rule matches nothing in `tests/logs/`, or if it matches anything in
`tests/goodware/`.

```bash
yara <rule>.yar tests/logs/<sample> -c    # must be > 0
yara <rule>.yar tests/goodware/<sample> -c # must be 0
```

Sigma rules are validated with `sigma check` and by successful conversion to the
backends their platform targets. Behavioral testing against live telemetry
happens in the target SIEM.

## ⚠️ Malicious samples

`tests/logs/` contains **live malicious code** — functional webshells and other
samples used to validate detection logic. This is deliberate. Do not execute
anything in that directory, and expect endpoint security products to flag it on
clone.

`tests/goodware/` contains benign samples only.

## Local setup

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
sudo apt install yara
pre-commit install
```

Commits are SSH-signed and gated by pre-commit hooks: YAML validation,
`sigma check`, YARA compilation, and secret scanning.

## Deprecation

Rules that are superseded or no longer relevant move to `sigma/deprecated/` or
`yara/deprecated/` rather than being deleted. Detection history is useful.

Both directories are kept in the tree even while empty, each holding a
`.gitkeep`, so a deprecation has somewhere to go without restructuring the repo
first. `sigma/rules-emerging-threats/` is retained on the same basis, for
time-boxed rules covering an active campaign.
