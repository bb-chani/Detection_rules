# Detection_rules # Detection_rules

Vendor-neutral detection content written in [Sigma](https://sigmahq.io/) and
YARA, with CI validation and multi-backend conversion.

Detections are authored once in a portable format and compiled to the query
language of whichever platform needs them — no rewriting a rule three times
for three SIEMs.

## Why detection-as-code

Detection logic belongs in version control for the same reasons application
code does: peer review, change history, automated testing, and repeatable
deployment. Every rule here is linted on commit and validated in CI before merge.

## One rule, three platforms

`proc_creation_win_certutil_download.yml` detects `certutil.exe` being abused to
pull down remote payloads — a well-documented
[LOLBin](https://lolbas-project.github.io/lolbas/Binaries/Certutil/) technique
mapped to ATT&CK [T1105](https://attack.mitre.org/techniques/T1105/).

**Splunk** (`-t splunk -p splunk_windows`)
```spl
PASTE SPLUNK OUTPUT HERE
```

**Elasticsearch** (`-t lucene -p ecs_windows`)
```
PASTE LUCENE OUTPUT HERE
```

**Microsoft XDR** (`-t kusto -p microsoft_xdr`)
```kusto
DeviceProcessEvents
| where (FolderPath endswith "\\certutil.exe" or ProcessVersionInfoOriginalFileName =~ "CertUtil.exe")
    and (ProcessCommandLine contains "urlcache" or ProcessCommandLine contains "verifyctl")
```

Each backend applies a field-mapping pipeline: Sysmon names for Splunk, ECS for
Elastic, `DeviceProcessEvents` schema for XDR.

## Repository layout

```
sigma/rules/              Production Sigma rules, by platform and logsource
sigma/rules-emerging-threats/   Time-boxed rules for active campaigns
sigma/deprecated/         Retired rules, kept for audit history
yara/rules/               YARA rules by family: loader, maldoc, webshell
tests/logs/               Sample telemetry for true-positive validation
tests/goodware/           Benign samples for false-positive testing
pipelines/                Custom Sigma field-mapping pipelines
```

## Usage

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pre-commit install

sigma check sigma/rules
sigma convert -t splunk -p splunk_windows sigma/rules/windows/process_creation/<rule>.yml
```

## Quality gates

Commits are gated by [pre-commit](https://pre-commit.com/): YAML syntax
validation, `sigma check` schema and UUID verification, and
[detect-secrets](https://github.com/Yelp/detect-secrets) scanning. All commits
are SSH-signed.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for rule conventions and the
false-positive testing process.
