# Security Policy

## Reporting a Vulnerability

This is a personal/educational security project (portfolio piece), but
responsible disclosure practices are followed regardless of project scale.

If you find a security issue in **PwEntropyChecker** — for example, a way the
password check could leak plaintext data, a flaw in the k-anonymity
implementation, or an API vulnerability — please report it privately rather
than opening a public issue.

**Contact:** reach out via [LinkedIn](https://www.linkedin.com/in/malik-muhammad-sanaullah-050m1y05f48/)
or [GitHub](https://github.com/SamSec404).

## Notes on This Project's Security Design

- Passwords submitted to the `/check` endpoint are processed in-memory and
  are never logged or persisted to disk or a database.
- Breach checking uses HaveIBeenPwned's k-anonymity endpoint — only the
  first 5 characters of a SHA-1 hash are ever sent externally. The full
  password and full hash never leave the server.
- This project is for educational/portfolio purposes and has not undergone
  a formal third-party security audit. Do not use it as-is in a production
  authentication system without further hardening (rate limiting, input
  validation, HTTPS enforcement, etc).
