# Security Policy

## Supported Versions

We release patches for security vulnerabilities in the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

## Reporting a Vulnerability

We take security seriously, especially given that this project handles certificate management and authentication.

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via one of the following methods:

1. **GitHub Security Advisories**: Use the [Security Advisory](https://github.com/ADORSYS-GIS/wazuh-cert-oauth2/security/advisories/new) feature to privately report vulnerabilities.

2. **Email**: Send an email to the maintainers at `selastlambou@gmail.com` or `yannick.siewe@gmail.com` with:
   - A description of the vulnerability
   - Steps to reproduce the issue
   - Potential impact assessment
   - Any suggested fixes (optional)

## What to Expect

- **Acknowledgment**: We will acknowledge receipt of your report within 48 hours.
- **Updates**: We will provide updates on the progress of addressing the vulnerability at least every 7 days.
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days.
- **Disclosure**: We will coordinate with you on the timing of public disclosure.

## Security Measures in This Project

This project implements several security best practices:

- **Dependency Scanning**: Automated vulnerability scanning via Dependabot and cargo-deny
- **Container Scanning**: Trivy scans for container image vulnerabilities
- **Secret Detection**: GitLeaks prevents accidental secret commits
- **Static Analysis**: Clippy and Super Linter for code quality
- **Supply Chain Security**: cargo-deny for license and advisory compliance

## Scope

The following are considered in-scope for security reports:

- Authentication/authorization bypasses
- Certificate validation issues
- Private key exposure risks
- Injection vulnerabilities
- Cryptographic weaknesses
- Container security issues

## Recognition

We appreciate the security research community's efforts in helping keep this project secure. Contributors who report valid security issues will be acknowledged in our release notes (unless they prefer to remain anonymous).
