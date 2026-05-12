# UNIX Hardening Suite

An automated security auditing and hardening tool for UNIX/Linux systems — developed for the Operating Systems Security course.

## Overview

This tool suite scans a Linux system for common security misconfigurations, rates its security posture on a 0-100 scale, applies fixes with user approval, and generates a before/after comparison report in HTML.

## Tools

| Program | File | Description |
|---------|------|-------------|
| Auditor | audit.sh | Scans for SUID/SGID files, world-writable directories, weak sudoers rules, open ports, insecure cron jobs, and outdated packages |
| Scorer | score.sh | Calculates a security score (0-100) based on findings severity |
| Remediator | fix.sh | Interactively fixes discovered vulnerabilities with user approval and automatic backups |

## Usage

sudo ./audit.sh
./score.sh
sudo ./fix.sh
sudo ./audit.sh
./score.sh

## Sample Output

Before Hardening: 25 / 100
After Hardening: 85 / 100

View the live report: https://ahmedmahdi7.github.io/unix-hardening-suite/HTML_comparison_report.html
## Checks Performed

- Suspicious SUID/SGID files
- World-writable directories (sticky bit verification)
- Weak sudoers rules (NOPASSWD, dangerous binaries)
- Open network ports
- Insecure cron jobs
- Outdated packages

## Requirements

- Linux/UNIX operating system
- Root privileges (for audit and remediation)
- Bash shell
