# Contributing

## Rule requirements

Every rule must pass CI before merge. Validation runs on push and pull request
via [`.github/workflows/validate.yml`](.github/workflows/validate.yml).

### Sigma

- Generate a fresh UUID per rule: `python3 -c "import uuid; print(uuid.uuid4())"`
- Required metadata: `title`, `id`, `status`, `description`, `author`, `date`,
  `logsource`, `detection`, `falsepositives`, `level`
- Map to [ATT&CK](https://attack.mitre.org/) via `tags` where applicable
- `falsepositives` must list real scenarios, not "unknown"
- Rules must convert cleanly to all three backends (Splunk, Elasticsearch,
  Microsoft XDR) — CI enforces this
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

Sigma rules are validated with `sigma check` and by successful conversion to all
backends. Behavioral testing against live telemetry happens in the target SIEM.

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
