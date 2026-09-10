# WooCommerce Security Scanner

A static analysis (SAST) tool built specifically for WooCommerce/WordPress
plugins. Combines AST-based taint analysis (via
[nikic/php-parser](https://github.com/nikic/PHP-Parser)) with a
WooCommerce-aware rule set — injection, XSS, broken access control,
hardcoded secrets — and suggests fixes for what it finds.

Generic PHP SAST tools don't know that `wp_ajax_nopriv_...` means
"reachable by anyone on the internet," or that `$wpdb->prepare()` is the
right way to parameterize a query. This scanner bakes that WordPress
knowledge straight into its rules.

## Quick start

```bash
git clone https://github.com/thyranystrom/scanner.git
cd scanner
pip install -r requirements.txt
cd scanner/php && composer install && cd ../..

python -m scanner.main path/to/plugin
python -m scanner.main path/to/plugin --triage        # HIGH/CRITICAL only
python -m scanner.main path/to/plugin --fix-apply      # auto-apply safe fixes (backed up first)

pytest && ruff check scanner/ tests/ && mypy scanner/
```


## Regression test plugin (`scanner-vuln-test`)

Detection is regression-tested in CI against a **separate** public repo:

**https://github.com/thyranystrom/scanner-vuln-test**

That repo holds an intentionally vulnerable WooCommerce-style plugin (**lab only — never deploy**). On every push/PR, Actions clones it, runs this scanner, and **fails the build if zero HIGH/CRITICAL findings** are reported — so a broken rule cannot ship silently.

## What it detects

[**OWASP Top 10:2025**](https://owasp.org/Top10/2025/) mapping:

| Category | Technique |
|---|---|
| A01 Broken Access Control | Cross-file AJAX/REST resolution, nonce/capability checks, taint-required SSRF |
| A02 Security Misconfiguration | `WP_DEBUG`, `phpinfo()` disclosure |
| A03 Software Supply Chain Failures | `composer audit` integration |
| A04 Cryptographic Failures | Weak hashing, hardcoded credentials |
| A05 Injection | AST taint analysis, `sprintf()`-bypass detection, dynamic `include` |
| A06 Insecure Design | Hard-coded auth-bypass flags, unresolved security TODOs |
| A07 Authentication Failures | Password comparison without a secure hash API |
| A08 Software/Data Integrity | `unserialize()` with user-input proximity |
| A09 Logging/Alerting Failures | Access denial with no nearby log call |
| A10 Exceptional Conditions | Empty catch blocks, `@`-suppressed calls |

**Plus:** inter-procedural taint tracking, an automated fix engine with
backups, confidence scoring instead of binary flags, and a persistent AST
cache.

## Inter-procedural taint tracking

Taint follows `$this->method()` calls within the same class:

```php
class Handler {
    public function get_input() { return $_POST['data']; }      // taint originates here
    public function process() {
        global $wpdb;
        $data = $this->get_input();                              // no $_POST reference itself...
        $wpdb->query("... $data ...");                           // ...but this IS a real SQLi
    }
}
```

Before this, the sink in `process()` was invisible — nothing about the
call itself references `$_POST`. The scanner resolves `$this->` calls
against the real method body, tracks parameter taint in and return-value
taint out, and reports sinks inside the callee too. Details in
`ASTAnalyzer`, [`scanner/dataflow.py`](./scanner/dataflow.py).

## Validated against real code

Run against the official
[WooCommerce Stripe Gateway](https://github.com/woocommerce/woocommerce-gateway-stripe)
(~200 files), not just its own fixtures. Typical result: 0 HIGH, a
handful of MEDIUM/LOW — several of those are false positives once you
read the code (empty `catch` guarded by `@codingStandardsIgnoreLine`,
`md5` used as a cache key not a password hash, masked `whsec_***`
placeholders). Earlier runs also had HIGH false positives — `system`
matching inside a string literal, an example `sk_live_` key in a doc
comment — both root-caused, fixed, and regression-tested.
**This tool surfaces candidates for review, not confirmed exploits.**

## Security issues found in the scanner itself

Tested against its own worst-case input. Five real issues found, each
with a regression test in
[`tests/test_security_self.py`](./tests/test_security_self.py):

1. **Path traversal via symlinks** — a symlinked file pointing outside
   the scan root (e.g. at `wp-config.php`) was silently read. Found in
   two independent code paths; both now verify the resolved path stays
   inside the scan root.
2. **Incomplete secret redaction** — only 4 known credential formats were
   redacted before writing reports; a generic password reached JSON/MD
   output in plaintext. Fixed with a generic `name = 'value'` fallback.
3. **Unsafe autofix writes** — `--fix-apply` had no path containment at
   the write step, no backup before overwriting. Fixed with a
   containment check plus an automatic `.bak` file.
4. **Report/baseline writes could follow a symlink, weren't atomic** —
   fixed with a helper that refuses symlinks and writes via temp+rename.
5. **A newline in a filename could inject a bogus path** into the batch
   AST-parsing protocol (one path per line over stdin). Fixed by
   rejecting any path containing `\n`/`\r` before scanning it.

The scanner is also run against its own repository as a sanity check:
`python -m scanner.main .` finds 0 findings outside the gitignored local
test fixture. The one real `.php` file shipped in this repo
([`scanner/php/dump_ast.php`](./scanner/php/dump_ast.php)) is clean.

## Known limitations

1. SSRF detection has no allowlist awareness for internally-built URLs.
2. `isset()` guards are only recognized on the same line as the access.
3. `@codingStandardsIgnoreLine` isn't treated as a suppression (only the
   scanner's own `phpcs:ignore` is).
4. Inter-procedural taint is intra-class, single-file only.
5. Taint doesn't follow a variable interpolated inside one branch of a
   ternary (`echo $cond ? "Hi $name" : "Hello";` with `$name` from
   `$_GET`) — the line is still flagged, just with a less useful "best"
   variable named in the evidence.

## Architecture

```
scanner/
  main.py, ast_engine.py, ast_cache.py   CLI, PHP-parser bridge, disk cache
  dataflow.py                            AST taint analysis + regex fallback
  confidence.py, fp_reducer.py           Scoring, false-positive reduction
  models.py, autofix.py, triage.py       Finding type, fix engine, triage
  deps.py, project.py, deep.py           Dependency scan, cross-file index
  limits.py                              Resource bounds for untrusted input
  rules/                                 One module per rule family (WC-*)
  php/dump_ast.php                       nikic/php-parser -> JSON AST
```

## Adding a new rule

1. Create `scanner/rules/my_rule.py` with
   `scan_my_rule(path, text, project=None) -> list[Finding]`.
2. Build each hit as a `Finding` (`rule_id`, `severity`, `title`, `file`,
   `line`, `message`, `owasp`, `confidence`; optional `evidence`/`source`/`sink`).
3. Register it in `scanner/rules/__init__.py` → append to `RULES`.
4. Add a fixture under `tests/fixtures/` and a test expecting the finding
   (plus a "safe" case that must not flag).
5. `pytest -q` and scan a small sample to sanity-check.

Copying an existing module (`dangerous_functions.py` is short) is usually
faster than starting blank.

## Test coverage

165 tests, including a dedicated suite that reproduces and guards
against every issue above so none of them can quietly come back.

CI runs lint → tests → security scan on every push
([`.github/workflows/security-scan.yml`](./.github/workflows/security-scan.yml)) —
the badge at the top links to the latest run.
