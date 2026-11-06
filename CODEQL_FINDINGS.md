# CodeQL Findings: Triage and Recommended Fixes

**Date:** 2026-11-06
**Commit analyzed:** `2612cfa2b` (branch `main`)
**Workflow replicated:** [.github/workflows/CodeQL.yml](.github/workflows/CodeQL.yml)
**GitHub code scanning results:** [Security → Code scanning](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+tool%3ACodeQL)

> No fixes have been applied. This document only describes the recommended changes.

## 1. How the scan was run

The workflow runs `github/codeql-action` for `javascript` with the default query suite and no custom build. It was
reproduced locally with the CodeQL CLI:

| Item | Value |
| --- | --- |
| CodeQL CLI | 2.27.4 |
| Query pack | `codeql/javascript-queries@2.5.0` |
| Query suite | `javascript-code-scanning.qls` (the default suite used by `codeql-action/analyze`) |
| Build mode | `none` (JavaScript/TypeScript extraction; same as Autobuild for JS) |

```sh
codeql database create medplum-db --language=javascript --source-root=. --build-mode=none --threads=0
codeql database analyze medplum-db \
  codeql/javascript-queries:codeql-suites/javascript-code-scanning.qls \
  --format=sarif-latest --output=results.sarif --threads=0
```

## 2. Summary of results

The scan produced **50 alerts** from 11 rules. Each alert was checked by reading the flagged code and following the
dataflow path in the SARIF output.

The **GitHub alerts** links open the repository's code-scanning page filtered to open alerts on `main` for that rule.
They show the alerts that the same workflow raised on GitHub. Viewing them requires write access to the repository.
Where a rule has more than one alert, use the file path given in this document to pick the right one. GitHub's run may
use a newer CodeQL bundle (`codeql-action` v4.39.1) than the local run (CLI 2.27.4), so the counts can differ slightly.

| Rule | Count | Verdict | GitHub alerts |
| --- | --- | --- | --- |
| `js/redos` | 1 | **True positive (#1)** | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fredos) |
| `js/zipslip` | 1 | **True positive (#2)** | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fzipslip) |
| `js/polynomial-redos` | 2 | **True positives (#3, #5)** | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fpolynomial-redos) |
| `js/stack-trace-exposure` | 1 | **True positive (#4)**, as information exposure. The leaked data is the error message, not the stack trace. | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fstack-trace-exposure) |
| `js/missing-rate-limiting` | 30 | False positive. See §4. | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fmissing-rate-limiting) |
| `js/loop-bound-injection` | 5 | False positive. See §4. | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Floop-bound-injection) |
| `js/incomplete-url-substring-sanitization` | 4 | False positive (test code). See §4. | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fincomplete-url-substring-sanitization) |
| `js/sql-injection` | 2 | False positive (validated input). See §4. | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fsql-injection) |
| `js/missing-token-validation` | 2 | False positive. See §4. | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fmissing-token-validation) |
| `js/command-line-injection` | 1 | False positive (validated input). See §4. | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fcommand-line-injection) |
| `js/insecure-randomness` | 1 | False positive. See §4. | [View](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Finsecure-randomness) |

## 3. True positives

### TP #1: Exponential ReDoS in the docs generator

- **Rule:** `js/redos` (CWE-1333)
- **GitHub alert:** [js/redos on `main`](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fredos)
- **Location:** [packages/generator/src/docs.ts:373](packages/generator/src/docs.ts#L373)
- **Severity:** Low. This is build-time tooling, and the input is the downloaded FHIR spec.

```ts
const typeLinks = Array.from(text.matchAll(/\[\[\[([A-Z][a-z]*)*\]\]\]/gi));
```

**Problem.** The `i` flag makes `[A-Z]` and `[a-z]` match the same characters. The group `([A-Z][a-z]*)*` therefore
works like `(\w\w*)*`. A nested quantifier over overlapping character classes backtracks exponentially when the closing
`]]]` is missing.

**Evidence.** Measured locally with Node:

| Input | Time |
| --- | --- |
| `'[[[' + 'a'.repeat(28) + '!'` | 49 ms |
| `'[[[' + 'a'.repeat(30) + '!'` | 208 ms |
| `'[[[' + 'a'.repeat(32) + '!'` | **~141 s** |

A single 35-byte string in a FHIR definition's description stalls the docs build for minutes.

**Recommended fix.** Remove the nested quantifier. The outer `*` adds nothing, and the `i` flag is not needed when the
character class already covers both cases:

```diff
-  const typeLinks = Array.from(text.matchAll(/\[\[\[([A-Z][a-z]*)*\]\]\]/gi));
+  const typeLinks = Array.from(text.matchAll(/\[\[\[([A-Za-z]+)\]\]\]/g));
```

This matches the same strings as before in linear time: the same input with 26,000 letters took 2 ms. It also fixes a
small existing bug. With a repeated group, `match[1]` held only the last repetition, not the whole type name.

---

### TP #2: Zip Slip (arbitrary file write) when extracting the FHIR spec

- **Rule:** `js/zipslip` (CWE-22)
- **GitHub alert:** [js/zipslip on `main`](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fzipslip)
- **Location:** [packages/generator/src/docs.ts:423-432](packages/generator/src/docs.ts#L423-L432)
- **Severity:** Low to medium. The archive is downloaded over HTTPS from a fixed URL. If that source or a mirror is
  compromised, it can write files anywhere on the developer or CI machine.

```ts
.on('entry', function (entry) {
  const fileName = entry.path;
  const fullPath = path.join(outputFolder, fileName).replaceAll('\\', '/');
  ...
  entry.pipe(fs.createWriteStream(fullPath));
```

**Problem.** `entry.path` comes from the archive and is not checked. An entry named `../../../.bashrc` or
`../../packages/server/src/app.ts` passes through `path.join` and is written outside `outputFolder`.

**Recommended fix.** Resolve the destination and reject any entry that falls outside the output folder:

```diff
+  const outputRoot = path.resolve(outputFolder);
   await new Promise<void>((resolve, reject) => {
     fs.createReadStream(zipFilePath)
       .pipe(unzipper.Parse())
       .on('entry', function (entry) {
         const fileName = entry.path;
         const type = entry.type;
-        const fullPath = path.join(outputFolder, fileName).replaceAll('\\', '/');
+        const resolvedPath = path.resolve(outputRoot, fileName);
+        if (resolvedPath !== outputRoot && !resolvedPath.startsWith(outputRoot + path.sep)) {
+          entry.autodrain();
+          reject(new Error(`Refusing to extract zip entry outside of output folder: ${fileName}`));
+          return;
+        }
+        const fullPath = resolvedPath.replaceAll('\\', '/');
```

Do the containment check before normalizing backslashes, because `path.sep` is `\` on Windows. Pinning a checksum for
the downloaded zip would add a second layer of protection.

---

### TP #3: Polynomial ReDoS in CDS Hooks prefetch templating (`@medplum/core`)

- **Rule:** `js/polynomial-redos` (CWE-1333)
- **GitHub alert:** [js/polynomial-redos on `main`, the alert in `packages/core/src/cds.ts`](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fpolynomial-redos)
- **Location:** [packages/core/src/cds.ts:259](packages/core/src/cds.ts#L259)
- **Severity:** Medium. This is library code that runs in browsers and Node, on input from a remote system.

```ts
export function replaceQueryVariables(user, context, query: string): string {
  return query.replaceAll(/\{\{([^}]+)\}\}/g, (substring, varName) => { ... });
```

**Source of input.** `query` is a prefetch template taken from `service.prefetch`
([cds.ts:195-209](packages/core/src/cds.ts#L195-L209)). Those templates come from the **external CDS service's
discovery document**, so a malicious or compromised CDS service controls them.

**Problem.** `[^}]+` also matches `{`. On a string of many `{` characters with no closing `}}`, the engine tries an
O(n) match from each of n starting positions, which is O(n²) in total.

**Evidence.** Measured locally with Node:

| Input | Time |
| --- | --- |
| `'{'.repeat(10_000)` | 43 ms |
| `'{'.repeat(20_000)` | 182 ms |
| `'{'.repeat(40_000)` | 717 ms |

Time roughly quadruples each time the input doubles. A few hundred KB freezes the UI thread of a client app, or the
event loop of a server or bot that calls the CDS helpers.

**Recommended fix.** Exclude `{` from the variable-name class so no starting position can extend across another
opening brace:

```diff
-  return query.replaceAll(/\{\{([^}]+)\}\}/g, (substring, varName) => {
+  return query.replaceAll(/\{\{([^{}]+)\}\}/g, (substring, varName) => {
```

With this change, `'{'.repeat(40_000)` takes 0 ms. Valid tokens such as `{{context.patientId}}` and `{{userPractitionerId}}`
never contain `{`, so legitimate templates behave the same. Consider also capping `query.length` (for example at
2,048 characters) before templating.

---

### TP #4: Internal error messages returned to unauthenticated callers of `/auth/newuser`

- **Rule:** `js/stack-trace-exposure`, which is really information exposure through an error message (CWE-209)
- **GitHub alert:** [js/stack-trace-exposure on `main`](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fstack-trace-exposure)
- **Locations:**
  - [packages/server/src/auth/newuser.ts:74-75](packages/server/src/auth/newuser.ts#L74-L75)
  - [packages/server/src/auth/newuser.ts:120-121](packages/server/src/auth/newuser.ts#L120-L121)
  - Sink: [packages/server/src/fhir/outcomes.ts:60](packages/server/src/fhir/outcomes.ts#L60)
- **Severity:** Low to medium. The endpoint is public and only behind reCAPTCHA
  ([auth/routes.ts:32](packages/server/src/auth/routes.ts#L32)).

```ts
} catch (err) {
  sendOutcome(res, normalizeOperationOutcome(err));
}
```

**Problem.** `normalizeOperationOutcome` turns any `Error` into `badRequest(err.message)`. The `try` block covers
`createUser`, `tryLogin`, and `sendVerificationEmail`. Low-level errors from those calls are therefore sent to an
anonymous caller as HTTP 400 responses. Examples include Postgres errors with table and constraint names, Redis
errors, and nodemailer and SMTP errors from [email/email.ts:136-145](packages/server/src/email/email.ts#L136-L145),
which can include the SMTP host, port, and server auth responses.

The server's global `errorHandler` was written to prevent this. Unknown errors are logged and replaced with
`500 {"msg":"Internal Server Error"}` ([app.ts:189-190](packages/server/src/app.ts#L189-L190)). `newuser.ts`
catches errors before they reach that handler.

CodeQL calls this a stack trace, but `normalizeErrorString` returns only `error.message`, not `error.stack`.
The information exposure is still real.

**Recommended fix.** Pass through only intentional `OperationOutcomeError`s or `OperationOutcome`s. Log everything
else and return a generic message:

```diff
   } catch (err) {
-    sendOutcome(res, normalizeOperationOutcome(err));
+    if (err instanceof OperationOutcomeError || isOperationOutcome(err)) {
+      sendOutcome(res, normalizeOperationOutcome(err));
+    } else {
+      getLogger().error('New user registration failed', err);
+      sendOutcome(res, serverError(new Error('Registration failed')));
+    }
   }
```

Make the same change at line 75, or rethrow and let the global `errorHandler` respond. A shared helper such as
`sendSafeOutcome(res, err)` would let other public auth handlers (`/auth/newproject`, `/auth/newpatient`) use the same
rule.

---

### TP #5: Polynomial ReDoS in the CDK RDS storage-type check

- **Rule:** `js/polynomial-redos` (CWE-1333)
- **GitHub alert:** [js/polynomial-redos on `main`, the alert in `packages/cdk/src/backend.ts`](https://github.com/JustSlightly4/medplum-secure/security/code-scanning?query=is%3Aopen+branch%3Amain+rule%3Ajs%2Fpolynomial-redos)
- **Location:** [packages/cdk/src/backend.ts:201](packages/cdk/src/backend.ts#L201)
- **Severity:** Low. The input is `config.rdsInstanceType` from the deployer's own CDK config. It is a real defect but
  not something a remote attacker can trigger.

```ts
storageType: writerInstanceType?.match(/^\w+d\w*\./i)
```

**Problem.** `\w+`, `d`, and `\w*` all overlap. On a long run of `d` characters without a `.`, the engine tries
O(n²) ways to split the input.

**Evidence.** `'d'.repeat(10_000)` took 50 ms, `'d'.repeat(20_000)` took 206 ms, and `'d'.repeat(40_000)` took 992 ms.

**Recommended fix.** Parse the instance family directly instead of using a backtracking regex. The intent is to check
whether the family (for example `r6gd` in `r6gd.xlarge`) has a `d` after its first character:

```diff
+      const instanceFamily = writerInstanceType?.split('.')[0] ?? '';
       ...
-        storageType: writerInstanceType?.match(/^\w+d\w*\./i)
+        storageType: writerInstanceType?.includes('.') && /d/i.test(instanceFamily.slice(1))
           ? DBClusterStorageType.AURORA_IOPT1
           : DBClusterStorageType.AURORA,
```

If you prefer to keep a regex, `/^\w[^\Wd]*d\w*\./i` removes the ambiguity: the first `d` after position 0 is the only
place the split can happen, so matching is linear. Both alternatives were checked against the original regex and gave
the same result for `r6gd.xlarge`, `m5d.2xlarge`, `x2iedn.large`, `R6GD.XLARGE`, `dd.large` (all IO-optimized),
`r6g.xlarge`, `d.large`, `big`, and `db.r6gd.xlarge` (all standard). The `d`-filled input that took 992 ms now runs in
0 ms. The original regex also returns standard for `db.r6gd.xlarge`. That is fine because the CDK config omits the
`db.` prefix, but it is worth a unit test.

## 4. Why the remaining alerts are false positives

- **`js/missing-rate-limiting` (30).** Every request passes through the global `rateLimitHandler(config)`, registered
  at [app.ts:222](packages/server/src/app.ts#L222) before any router. Auth and MFA routes also have dedicated limiters
  ([auth/mfalimit.ts](packages/server/src/auth/mfalimit.ts)). CodeQL only recognizes well-known packages such as
  `express-rate-limit`, so it does not see these custom limiters.
- **`js/sql-injection` (2), [admin/super.ts:741, 792](packages/server/src/admin/super.ts#L741).** Both handlers
  require super-admin access. Table names are validated with `isValidPostgresIdentifier` (`/^\w+$/`), which rules out
  quotes. Setting names must be keys of `OVERRIDABLE_TABLE_SETTINGS`, and values are validated as int or float by
  `express-validator` with `checkExact()`. CodeQL does not model these custom validators.
- **`js/command-line-injection` (1), [agent/src/upgrader.ts:82](packages/agent/src/upgrader.ts#L82).** The tainted
  `version` is passed through `assertValidMedplumSemver` (`/^\d+\.\d+\.\d+(-[0-9a-z]{7})?$/`) in
  `fetchLatestVersionString`, and `argv[3]` is checked with `isValidMedplumSemver`. No shell metacharacters can reach
  `binPath`. Using `spawnSync(binPath, ['/S'])` without `shell: true` would still be cleaner defense in depth.
- **`js/loop-bound-injection` (5).** Every sink loops over an object that is guaranteed to be a real array:
  `Array.isArray` in `evalFhirPath`, `constructor === Array` in `patch/util.ts clone`, and arrays built locally in
  `validateAccessPolicies`, `readReferences`, and `flatMapFilter`. An attacker-supplied `{length: 1e9}` object cannot
  reach these loops.
- **`js/missing-token-validation` (2), [oauth/routes.ts:14-15](packages/server/src/oauth/routes.ts#L14-L15).** The
  cookie only identifies an existing login for the OAuth `/authorize` endpoint. The resulting code goes only to the
  client's registered `redirect_uri`, and PKCE and `state` protect the flow as the OAuth spec requires. A CSRF token
  adds nothing beyond the equivalent `GET /authorize`.
- **`js/insecure-randomness` (1), [core/src/bundle.ts:72](packages/core/src/bundle.ts#L72).** `generateId()` uses
  `crypto.randomUUID()` and falls back to `Math.random()` only in non-secure browser contexts. The value is used as a
  temporary `urn:uuid` placeholder for local references in a transaction bundle, which is not a security-sensitive use.
- **`js/incomplete-url-substring-sanitization` (4),
  [react/src/CcdaDisplay/CcdaDisplay.test.tsx](packages/react/src/CcdaDisplay/CcdaDisplay.test.tsx#L43).** These are
  `url.includes(...)` checks inside Jest fetch mocks used to route test requests. They are not used for sanitization.
  You could exclude `**/*.test.ts(x)` with a `paths-ignore` entry in a CodeQL config file to reduce noise.
