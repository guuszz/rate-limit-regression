# Security policy

This repository contains a synthetic loopback-only test fixture. It is not intended to probe third-party services.

## Supported scope

- Use the demo against the bundled local fixture only.
- Do not put real passwords, activation tokens, personal data, or customer data in test inputs or reports.
- The tool accepts only literal loopback IP addresses, connects directly without configured proxies, and does not follow redirects; do not weaken these guards to test third-party systems.
- The in-memory limiter is a demo implementation, not production-grade distributed rate limiting.

For issues in this repository, open a GitHub issue without secrets or personal data. If a report involves a third party, use that provider's responsible-disclosure channel rather than publishing operational details here.
