# Detection_rules

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
Image="*\\certutil.exe" OR OriginalFileName="CertUtil.exe" CommandLine IN ("*urlcache*", "*verifyctl*")
```

**Elasticsearch** (`-t lucene -p ecs_windows`)
```
(process.executable.caseless:*\\certutil.exe OR process.pe.original_file_name:CertUtil.exe) AND (process.command_line:(*urlcache* OR *verifyctl*))
```

**Microsoft XDR** (`-t kusto -p microsoft_xdr`)
```kusto
DeviceProcessEvents
| where (FolderPath endswith "\\certutil.exe" or ProcessVersionInfoOriginalFileName =~ "CertUtil.exe")
    and (ProcessCommandLine contains "urlcache" or ProcessCommandLine contains "verifyctl")
```

Each backend applies a field-mapping pipeline: Sysmon names for Splunk, ECS for
Elastic, `DeviceProcessEvents` schema for XDR.

## Custom field mapping

Stock pipelines cover Sysmon, ECS and XDR, but Okta's system log has no built-in
ECS mapping. [`pipelines/okta_ecs.yml`](pipelines/okta_ecs.yml) supplies one, so
Okta rules stay written in Okta's own field names and get translated at compile
time:

```yaml
eventtype:                    event.action
actor.alternateId:            user.name
client.ipAddress:             source.ip
debugContext.debugData.risk:  okta.debug_context.debug_data.risk_level
```

`okta_suspicious_session_activity.yml` selects on `eventtype` and Okta's risk
string. One rule, two backends:

**Splunk** (`-t splunk --without-pipeline`) — raw Okta field names, as the
platform receives them
```spl
eventtype IN ("user.session.start", "user.authentication.auth_via_mfa") debugContext.debugData.risk="*HIGH*"
```

**Elasticsearch** (`-t lucene -p pipelines/okta_ecs.yml`) — ECS names, plus the
dataset scope the pipeline adds
```
event.dataset:okta.system AND ((event.action:(user.session.start OR user.authentication.auth_via_mfa)) AND okta.debug_context.debug_data.risk_level:*HIGH*)
```

The Elastic Okta integration parses the raw `level=HIGH reasons=...` string into
discrete keyword fields, which is why `debugContext.debugData.risk` resolves to
`risk_level` rather than passing through unchanged. Without the mapping the rule
still compiles — it just never matches.

## Behavioral YARA

`Webshell_PHP_Generic_Eval` looks for the *shape* of a webshell rather than any
particular one: request data reaching a code execution function.

```
condition:
    filesize < 200KB
    and $php_open
    and any of ($exec_*)      // eval, assert, system, shell_exec, passthru
    and any of ($src_*)       // $_GET, $_POST, $_REQUEST, $_COOKIE
```

Requiring both halves is what keeps it useful. Every rule ships with a matching
pair that demonstrates the distinction:

```php
// tests/logs/webshell_sample.php      -> matches
<?php eval($_GET["cmd"]); ?>

// tests/goodware/benign_get.php       -> does not match
<?php echo "Hello, " . $_GET["name"]; ?>
```

Both read `$_GET`. Only one passes it to an execution sink — a signature on the
input alone would flag ordinary PHP. The `filesize` bound comes first so the
condition short-circuits before any string scanning.

CI enforces the pair on every rule: it fails if a rule matches nothing in
`tests/logs/`, and fails if it matches anything in `tests/goodware/`.

```bash
yara yara/rules/webshell/webshell_php_generic_eval.yar tests/logs/webshell_sample.php -c   # 1
yara yara/rules/webshell/webshell_php_generic_eval.yar tests/goodware/benign_get.php -c    # 0
```

> `tests/logs/` holds live malicious samples by design. Don't execute anything in
> it, and expect endpoint security to flag it on clone.

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
