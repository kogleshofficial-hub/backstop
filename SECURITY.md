# Security policy

BACKSTOP is early-stage software. Do not rely on the browser console or scenario runner to protect production systems, personal data, money, or critical infrastructure.

## Reporting a vulnerability

Please do not publish credentials, personal data, or a working exploit in a public issue. Use GitHub's private vulnerability reporting feature for this repository if it is enabled. If private reporting is unavailable, contact the repository maintainer privately before sharing sensitive details.

Include the affected version or commit, impact, reproduction steps that do not expose real users or systems, and any relevant logs with secrets removed.

## Current security boundary

The TypeScript evaluator returns policy decisions; it does not authenticate agents or execute actions. Browser-held rules, approvals, and logs are controlled by the browser owner and are not trusted server records. The current project is not a production security boundary.

Before production use, the project needs server-side enforcement at the exact tool-call boundary, authenticated identities, least-privilege authorization, tenant isolation, approval expiry and replay protection, trusted audit storage, adversarial integration tests, dependency review, and independent security assessment.
