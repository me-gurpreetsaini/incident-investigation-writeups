# Incident Investigation Write-Ups

Professional incident reports based on public blue team challenges and packet captures. Each report follows the same structure: executive summary, timeline, technical analysis with screenshot evidence, indicators of compromise (IOCs), root cause, MITRE ATT&CK mapping, and recommendations.

The goal is to practice what a SOC analyst does after the detection: work out what happened, prove it with evidence, and explain it clearly to both technical and non-technical readers.

## Reports

| # | Case | Source | Severity | Skills shown |
|---|---|---|---|---|
| 01 | [Port Scan to Web Shell and Reverse Shell](reports/01-btlo-network-analysis-web-shell.md) | Blue Team Labs Online (Network Analysis – Web Shell) | High | PCAP analysis, SYN scan detection, web attack tools, web shell and reverse shell analysis |

More cases are planned.

## Method

- Evidence is analysed in an isolated virtual machine with networking disabled.
- Every finding in a report is backed by a Wireshark filter and a screenshot.
- Times are given in UTC.
- Anything I could not prove is stated in the report instead of guessed.
- Only retired challenges are published, in line with the platform's rules.

## Tools

Wireshark, MITRE ATT&CK, Markdown

## Repo layout

- `reports/` – the incident reports
- `images/` – evidence screenshots used in the reports
- `templates/` – the report template used for every case
