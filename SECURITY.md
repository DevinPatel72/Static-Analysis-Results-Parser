# Security Policy

## Supported Versions

Security fixes are only applied to the latest release of the Static Analysis Results Parser (SARP).

Older releases will not receive security updates. Users are encouraged to upgrade to the latest release to receive available security fixes.

## Reporting a Vulnerability

If you discover a potential security vulnerability in SARP, please report it privately rather than opening a public GitHub issue.

**Preferred reporting method:** Use [GitHub's private vulnerability reporting feature](https://github.com/DevinPatel72/Static-Analysis-Results-Parser/security/advisories/new).

If private vulnerability reporting is unavailable, contact the repository maintainer through the contact information provided in [maintainers.md](maintainers.md).

Please do not publicly disclose the vulnerability until it has been investigated and the maintainer has had a reasonable opportunity to address it.

## Information to Include

When reporting a vulnerability, please include as much of the following information as possible:

* A description of the vulnerability and its potential impact.
* The affected SARP version or release.
* The operating system and relevant environment details.
* Steps to reproduce the issue.
* A proof of concept or sample input, if applicable.
* Any suggested mitigations or fixes.

Please avoid including confidential information, credentials, or sensitive production data in your report.

## Scope

Security reports relevant to SARP may include, but are not limited to:

* Arbitrary code execution or command injection.
* Path traversal or unauthorized file access.
* Unsafe handling of untrusted scanner output or input files.
* Denial of service caused by malformed or specially crafted input.
* Insecure handling of configuration files or externally supplied data.
* Vulnerabilities in dependencies that affect SARP.

Reports concerning vulnerabilities in third-party tools or scanners should explain how the issue affects SARP or its handling of their output.

## Response and Disclosure

The maintainer will review submitted reports and make reasonable efforts to acknowledge them, investigate their validity and impact, and address confirmed vulnerabilities.

Response and remediation timelines may vary depending on the severity, complexity, and availability of a fix.

Once a vulnerability has been addressed, relevant details may be disclosed through a security advisory and/or release notes.

Please allow the maintainer a reasonable opportunity to investigate and resolve the issue before publishing technical details.
