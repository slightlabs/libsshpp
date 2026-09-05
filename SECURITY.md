# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately — **do not** open a public
GitHub issue.

* Preferred: use GitHub's private vulnerability reporting ("Report a
  vulnerability" under the repository's Security tab), which opens a private
  advisory visible only to maintainers.
* Alternative: email the maintainers at the address listed in the project's
  `CODEOWNERS`/repository metadata (to be filled in before the first public
  release).

Please include:

* The `libsshpp` version (or commit) and the linked `libssh` version
  (`sshpp::Library::version_string()`).
* A minimal reproduction, and whether the issue requires a malicious peer
  (server or client) versus a local/untrusted-input trigger.
* Your assessment of impact (memory safety, authentication bypass, host-key
  verification bypass, path traversal, etc.).

## Scope

In scope: memory-safety bugs, authentication or host-key verification
bypasses, path-traversal in the SFTP/SCP transfer helpers, and any behavior
that contradicts the security guarantees documented in
[docs/design/01 §1.5](docs/design/01-goals-and-scope.md#15-requirements) and
the README's Security section.

Out of scope: vulnerabilities in `libssh` itself (report those to the
[libssh project](https://www.libssh.org/security/)) and issues that require
the caller to have already disabled a documented safety mechanism (e.g.
`AcceptAnyHostKeyPolicy`, which requires an explicit
`i_understand_this_is_insecure()` opt-in).

## Response

We aim to acknowledge reports within 5 business days. Coordinated disclosure
timelines are negotiated case by case; a fix release is the goal before
public disclosure.

## Supported versions

Until the first `1.0.0` release, only the `main` branch receives security
fixes; see [11 — Versioning and roadmap](docs/design/11-versioning-and-roadmap.md)
for the post-1.0 support policy.
