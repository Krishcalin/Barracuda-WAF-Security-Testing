# CLAUDE.md — Barracuda WAF Security Testing

## Project Overview

Open-source Python-based security testing tool to assess and evaluate the security configuration of Barracuda Web Application Firewall (WAF) appliances. Connects via the Barracuda WAF REST API to audit policies, SSL/TLS settings, access controls, logging, and compliance posture.

## Planned Repository Structure

```
barracuda_waf_scanner.py          # Main scanner entry point (CLI)
config/
  default_profile.yaml            # Default scan profile (all checks enabled)
  compliance_maps.yaml            # CIS / vendor best-practice mappings
checks/
  __init__.py
  waf_policies.py                 # WAF rule sets, attack definitions, custom rules, action profiles
  ssl_tls.py                      # Certificates, cipher suites, TLS versions, HSTS, OCSP stapling
  access_control.py               # IP ACLs, geo-blocking, rate limiting, URL ACLs, brute-force prevention
  authentication.py               # Admin auth, LDAP/RADIUS/SAML, MFA, session timeout, password policy
  services.py                     # Virtual services, backend servers, load balancing, health checks
  network.py                      # Interfaces, VLANs, routing, HA/clustering, management access
  ddos_protection.py              # Slow client protection, connection limits, request limits, SYN flood
  bot_protection.py               # Bot mitigation, CAPTCHA, advanced bot detection, client fingerprinting
  api_security.py                 # JSON/XML validation, API discovery, schema enforcement, content-type checks
  logging_monitoring.py           # Syslog, SIEM export, audit logging, alert policies, log retention
  firmware_updates.py             # Firmware version, EOL status, available updates, vulnerability patches
utils/
  api_client.py                   # Barracuda WAF REST API client (token auth, session management)
  report_generator.py             # HTML + JSON report output (severity dashboard, findings, compliance)
  severity.py                     # Severity classification and scoring logic
tests/
  test_data/                      # Mock API responses for offline testing
  test_scanner.py                 # Unit tests for scanner checks
reports/                          # Generated scan reports (gitignored)
README.md
CLAUDE.md
LICENSE                           # MIT
requirements.txt                  # requests, pyyaml, jinja2, urllib3
.gitignore
```

## Architecture

### Barracuda WAF REST API

- **Base URL:** `https://<waf-ip>:8443/restapi/v3.2/`
- **Authentication:** Token-based — `POST /restapi/v3.2/login` with admin credentials returns an auth token
- **Key API endpoints:**
  - `/services` — Virtual services and backend server configurations
  - `/security-policies` — WAF security policies and rule sets
  - `/signed-certificate`, `/trusted-certificate` — SSL/TLS certificate management
  - `/system` — Firmware version, hostname, system settings
  - `/network` — Interface and VLAN configuration
  - `/access-control` — IP ACLs, URL ACLs, geo-blocking rules
  - `/rate-control` — Rate limiting policies
  - `/content-rules` — Content routing and rewrite rules
  - `/logging` — Syslog servers, log settings, audit log configuration

### Scanner Flow

1. **Connect** — Authenticate to Barracuda WAF REST API, obtain session token
2. **Discover** — Enumerate services, policies, certificates, network config
3. **Assess** — Run all enabled check modules against collected configuration
4. **Score** — Calculate posture score: `Score = 100 - (CRIT×15 + HIGH×5 + MED×2 + LOW×0.5)`
5. **Report** — Generate HTML + JSON reports with findings, severity breakdown, and compliance mapping

### Check Module Pattern

Each check module in `checks/` follows a standard pattern:
```python
class WafPoliciesChecker:
    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        self.check_attack_action_policy()
        self.check_request_limits()
        self.check_cookie_security()
        # ...
        return self.findings

    def check_attack_action_policy(self):
        policies = self.api.get("/security-policies")
        for policy in policies:
            if policy.get("attack-action") != "deny-and-log":
                self.findings.append({
                    "id": "WAF-POL-001",
                    "title": "Attack action not set to deny-and-log",
                    "severity": "HIGH",
                    "category": "WAF Policy",
                    "resource": policy["name"],
                    "actual": policy.get("attack-action"),
                    "expected": "deny-and-log",
                    "recommendation": "Set attack action to 'Deny and Log' to block attacks and retain audit trail",
                    "cis_ref": "4.1.1"
                })
```

## Security Check Categories

| Category | Checks | Focus Areas |
|----------|-------:|-------------|
| WAF Policies | ~25 | Attack actions, request limits, cookie security, parameter protection, URL normalization, data theft protection |
| SSL/TLS | ~15 | TLS 1.2+, strong ciphers, certificate expiry, HSTS, perfect forward secrecy, OCSP stapling |
| Access Control | ~15 | IP ACLs, geo-blocking, rate limiting, brute-force prevention, URL access rules |
| Authentication | ~12 | Admin MFA, password policy, session timeouts, LDAP/SAML config, role-based access |
| Services | ~12 | Backend SSL, health checks, connection pooling, persistence, instant SSL |
| Network | ~10 | Management access restrictions, HA config, VLAN isolation, interface security |
| DDoS Protection | ~10 | Slow client settings, connection limits, request rate caps, SYN flood protection |
| Bot Protection | ~8 | Bot detection, CAPTCHA, client fingerprinting, JavaScript challenge |
| API Security | ~8 | JSON/XML validation, content-type enforcement, schema validation, payload limits |
| Logging & Monitoring | ~10 | Syslog forwarding, SIEM integration, audit logging, log retention, alerting |
| Firmware & Updates | ~5 | Firmware version, EOL check, security patches, energize updates subscription |
| Content Rules | ~11 | URL rewriting, open redirects, response headers, CSP, X-Frame-Options, HSTS, Permissions-Policy |
| Adaptive Profiling | ~10 | Learning mode, URL/parameter profiles, positive security model, trusted host learning, auto-refresh |
| Backup & Recovery | ~9 | Scheduled backups, encryption, offsite/cloud backup, HA config sync, transfer protocol security |
| License & Capacity | ~10 | License status, throughput utilization, ATP, feature modules, SSL TPS, service limits |
| CVE Assessment | ~12 | Known CVE matching against firmware version, version gap analysis, vulnerability definition updates |

**Total: ~180 security checks across 16 categories**

## Key Conventions

- **Language:** Python 3.9+
- **CLI framework:** argparse
- **API client:** requests with retry logic and SSL verification options
- **Output formats:** HTML (self-contained dark-theme report) + JSON
- **Severity levels:** CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Finding IDs:** `{CATEGORY}-{SEQ}` format (e.g., `WAF-POL-001`, `SSL-003`, `ACL-012`)
- **Config:** YAML-based scan profiles for enabling/disabling check categories
- **Compliance mapping:** CIS Barracuda WAF Benchmark, vendor hardening guide, OWASP recommendations
- **No destructive operations** — read-only API calls, no configuration changes

## Development Guidelines

- All API calls must be read-only (GET requests only) — never modify WAF configuration
- Handle API authentication failures and token expiry gracefully
- Support `--insecure` flag for self-signed certificates (common in lab environments)
- Each check module is independently testable with mock API responses
- Findings must include actionable remediation steps specific to Barracuda WAF
- HTML reports should be self-contained (inline CSS/JS) matching the portal dark theme

## CLI Usage (Planned)

```bash
# Full scan with HTML + JSON reports
python barracuda_waf_scanner.py --host 192.168.1.100 --port 8443 --user admin --password <pass> --html report.html --json report.json

# Scan specific categories only
python barracuda_waf_scanner.py --host 192.168.1.100 --user admin --password <pass> --checks ssl,waf_policies,access_control

# Use scan profile
python barracuda_waf_scanner.py --host 192.168.1.100 --user admin --password <pass> --profile config/default_profile.yaml

# Skip SSL verification (lab/self-signed certs)
python barracuda_waf_scanner.py --host 192.168.1.100 --user admin --password <pass> --insecure
```
