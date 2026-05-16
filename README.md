# 🛡️ Web Attack Detection Rules

> **Wazuh + Sigma detection rules** covering the OWASP Top 10, MITRE ATT&CK web-layer techniques, and modern API attack vectors — purpose-built for real-world SOC environments.

---

## 📌 Overview

This repository contains **75 production-grade detection rules** across two formats:

| Format | Count | Location |
|--------|-------|----------|
| **Wazuh XML** | 75 rules | `wazuh/` |
| **Sigma YAML** | 75 rules | `web-attacks/` |

Rules are organized by attack category, mapped to MITRE ATT&CK, and maintained with full detection logic documentation. Each rule ships with: description, severity level, detection logic breakdown, MITRE tactic/technique mapping, false positive guidance, and author attribution.

---

## 📊 MITRE ATT&CK Coverage

### Overall

| Metric | Value |
|--------|-------|
| **Total Techniques Mapped** | 61 |
| ✅ Full Coverage (3+ rules) | **45 techniques — 73.8%** |
| ⚠️ Partial Coverage (1–2 rules) | **13 techniques — 21.3%** |
| ❌ No Coverage | **3 techniques — 4.9%** |
| 📊 **Total Coverage** | **58 / 61 — 95.1%** |

### Coverage by Tactic

| Tactic | Techniques Covered | Coverage |
|--------|--------------------|----------|
| TA0001 - Initial Access | 3 / 3 | ✅ 100% |
| TA0002 - Execution | 5 / 6 | ✅ 83% |
| TA0003 - Persistence | 2 / 4 | ⚠️ 50% |
| TA0004 - Privilege Escalation | 3 / 3 | ✅ 100% |
| TA0005 - Defense Evasion | 7 / 7 | ✅ 100% |
| TA0006 - Credential Access | 10 / 10 | ✅ 100% |
| TA0007 - Discovery | 6 / 6 | ✅ 100% |
| TA0008 - Lateral Movement | 2 / 2 | ✅ 100% |
| TA0009 - Collection | 4 / 5 | ⚠️ 80% |
| TA0010 - Exfiltration | 4 / 4 | ✅ 100% |
| TA0011 - Command and Control | 4 / 4 | ✅ 100% |
| TA0040 - Impact | 6 / 7 | ⚠️ 86% |
| TA0043 - Reconnaissance | 3 / 3 | ✅ 100% |

### Known Gaps

The following 3 techniques are **intentionally out of scope** for a web-layer ruleset — they require endpoint or email-level visibility beyond HTTP log sources:

| Technique | Reason Out of Scope |
|-----------|---------------------|
| **T1136.001** — Create Local Account | Requires OS/endpoint telemetry, not web logs |
| **T1114** — Email Collection | Requires mail server or DLP telemetry |
| **T1486** — Data Encrypted for Impact | Ransomware behavior; endpoint/EDR coverage required |

---

## 🗂️ Rule Categories

### Injection Attacks
| # | Rule | Severity |
|---|------|----------|
| R1 | SQL Injection Attack Detected | 🔴 Critical |
| R5 | LDAP Injection Detected | 🟠 High |
| R13 | NoSQL Database Injection | 🟠 High |
| R42 | Django ORM SQLi — Q() Object Injection | 🟠 High |
| R73 | XPath / XQuery Injection | 🟠 High |

### File Inclusion & Path Traversal
| # | Rule | Severity |
|---|------|----------|
| R2 | Directory Traversal Attack | 🟠 High |
| R6 | Remote File Inclusion (RFI) | 🔴 Critical |
| R7 | Local File Inclusion (LFI) | 🟠 High |
| R66 | PHP Wrapper Abuse — php:// phar:// data:// | 🔴 Critical |

### Authentication & Credential Attacks
| # | Rule | Severity |
|---|------|----------|
| R11 | Web Application Brute Force | 🟠 High |
| R45 | OTP/MFA Brute-Force Tool — Fuzzer Placeholder | 🟠 High |
| R52 | Password Reset Token Brute-Force | 🟠 High |
| R54 | Account Enumeration — High-Frequency Auth Scanning | 🟠 High |
| R63 | Session Fixation on Auth Endpoint | 🟠 High |

### SSRF & Out-of-Band Attacks
| # | Rule | Severity |
|---|------|----------|
| R44 | Django SSRF — URLValidator Bypass | 🟠 High |
| R46 | Blind SSRF via DNS Callback (OOB Domains) | 🟠 High |
| R56 | Host Header Injection — IP Literal | 🟠 High |
| R57 | Host Header Injection — Special Characters (@ #) | 🟠 High |
| R64 | SSRF — Cloud Metadata Service (AWS/GCP) | 🟠 High |

### Deserialization & RCE
| # | Rule | Severity |
|---|------|----------|
| R55 | Insecure Deserialization — Java/PHP/Python/.NET/Node.js | 🔴 Critical |
| R62 | Spring4Shell / Log4Shell / EL / SpEL Injection | 🔴 Critical |
| R3 | OS Command Injection | 🔴 Critical |

### Denial of Service
| # | Rule | Severity |
|---|------|----------|
| R43 | Django XML Algorithmic DoS — Deeply Nested XML | 🟠 High |
| R48 | Race Condition Attack — High-Frequency State-Changing Requests | 🟠 High |
| R69 | XML Entity Bomb — Recursive ENTITY Definitions (Billion Laughs) | 🟠 High |
| R70 | XML Entity Bomb — Excessive Entity References (15+) | 🟠 High |

### Injection via Data Formats
| # | Rule | Severity |
|---|------|----------|
| R58 | CSV / Formula Injection — Malicious Spreadsheet Keyword | 🟠 High |
| R59 | Critical CSV Injection — Confirmed Spreadsheet Upload | 🟠 High |
| R61 | Critical CSV Injection — DDE Pipe-Cell Syntax (RCE) | 🔴 Critical |
| R74 | Email Header Injection — CRLF in URL | 🟠 High |
| R75 | Email Header Injection — CRLF in POST Body | 🟠 High |

### Protocol & Transport Attacks
| # | Rule | Severity |
|---|------|----------|
| R65 | HTTP Request Smuggling — CL.TE / TE.CL Desync | 🔴 Critical |
| R60 | gRPC Protocol Detection — Service Discovery | 🟠 High |
| R12 | HTTP Response Splitting | 🟡 Medium |

### Web Application Logic & API Abuse
| # | Rule | Severity |
|---|------|----------|
| R49 | Web Cache Poisoning — Suspicious Unkeyed Header | 🟠 High |
| R50 | API Mass Assignment — Privilege Parameter Injection | 🔴 Critical |
| R67 | Prototype Pollution — `__proto__` in URL | 🟠 High |
| R68 | Prototype Pollution — URL-Encoded `__proto__` | 🟠 High |
| R71 | Open Redirect — External Domain via URL Parameter | 🟠 High |
| R72 | Open Redirect — External Domain in POST Body | 🟠 High |

---

## ⚙️ Rule Format

### Wazuh XML (Wazuh SIEM)

```xml
<rule id="300518" level="12">
  <if_sid>31100</if_sid>
  <field name="full_log" type="pcre2">
    (?i)(?:"is_admin"\s*:\s*true|"role"\s*:\s*"(?:admin|superuser|root)")
  </field>
  <description>API Mass Assignment Attempt: Injection of sensitive privilege parameters detected</description>
  <mitre>
    <id>T1190</id>
    <id>T1068</id>
  </mitre>
</rule>
```

### Sigma YAML (SIEM-agnostic)

```yaml
title: API Mass Assignment - Privilege Parameter Injection
status: experimental
logsource:
  category: webserver
detection:
  selection:
    cs-method: POST
    cs-uri|contains:
      - 'is_admin=true'
      - 'role=admin'
      - 'superuser=true'
  condition: selection
level: critical
```

---

## 🚀 Deployment

### Wazuh
1. Copy rules from `wazuh/` into `/var/ossec/etc/rules/`
2. Restart Wazuh manager: `systemctl restart wazuh-manager`
3. Verify with: `ossec-logtest`

### Sigma (Convert to your SIEM)
```bash
# Convert to Splunk SPL
sigma convert -t splunk web-attacks/web_50_api_mass_assignment.yml

# Convert to Elastic EQL
sigma convert -t eql web-attacks/web_62_spring4shell_log4shell.yml

# Convert all rules at once
sigma convert -t splunk web-attacks/*.yml
```

---

## 📁 Repository Structure

```
Web-Attacks-Detection-Rules/
├── web-attacks/               # Sigma YAML rules (R1–R75)
│   ├── web_01_sql_injection.yml
│   ├── web_42_django_orm_sqli.yml
│   └── web_75_email_header_injection.yml
├── wazuh/                     # Wazuh XML rules
│   └── web_attacks_rules.xml
├── docs/
│   └── MITRE_Coverage.xlsx    # Full ATT&CK mapping with coverage stats
└── README.md
```

---

## 🔢 Severity Distribution

| Severity | Count | Percentage |
|----------|-------|------------|
| 🔴 Critical | 14 | 18.7% |
| 🟠 High | 52 | 69.3% |
| 🟡 Medium | 7 | 9.3% |
| 🔵 Low | 2 | 2.7% |

---

## 👤 Author

**Ahmed Elnoury**  
SOC Engineer | Detection Engineering  
All rules authored, tested, and documented as part of an ongoing web-layer detection coverage initiative.

---

## 📄 License

This project is licensed for internal SOC and blue team use. Rules are provided as-is — always tune false positive thresholds for your specific environment before deploying to production.

---

*Last updated: Q2 2025 — 75 rules across 13 MITRE ATT&CK tactics*
