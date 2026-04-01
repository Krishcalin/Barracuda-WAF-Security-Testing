"""Access control security checks — IP ACLs, geo-blocking, rate limiting,
brute-force prevention, URL access rules."""

import logging

logger = logging.getLogger(__name__)


class AccessControlChecker:
    """Assess access control configurations across all services."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running access control checks...")
        services = self.api.get_services()

        for svc in services:
            name = svc.get("name", svc.get("id", "unknown"))
            acls = self.api.get_access_control(name)
            rate = self.api.get_rate_control(name)
            detail = self.api.get_service_detail(name)
            cfg = detail.get("data", detail) if isinstance(detail, dict) else svc

            self._check_global_acls(name, acls)
            self._check_geo_blocking(name, cfg)
            self._check_rate_limiting(name, rate, cfg)
            self._check_brute_force(name, cfg)
            self._check_url_acls(name, cfg)
            self._check_ip_reputation(name, cfg)
            self._check_trusted_hosts(name, cfg)

        return self.findings

    def _check_global_acls(self, name, acls):
        if not acls:
            self.findings.append({
                "id": "ACL-001",
                "title": "No global ACL rules configured",
                "severity": "MEDIUM",
                "category": "Access Control",
                "resource": name,
                "actual": "No ACL rules",
                "expected": "ACL rules restricting access by IP/network",
                "recommendation": "Configure global ACL rules to restrict access to known IP ranges and block suspicious sources"
            })
            return

        for acl in acls:
            action = acl.get("action", "")
            ip_range = acl.get("source-address", acl.get("ip-address", ""))
            if isinstance(ip_range, str) and ip_range in ("0.0.0.0/0", "*", "any"):
                if isinstance(action, str) and action.lower() == "allow":
                    self.findings.append({
                        "id": "ACL-002",
                        "title": "Global allow-all ACL rule detected",
                        "severity": "HIGH",
                        "category": "Access Control",
                        "resource": name,
                        "actual": f"Allow all from {ip_range}",
                        "expected": "Specific IP ranges in allow rules",
                        "recommendation": "Replace wildcard allow rules with specific trusted IP ranges"
                    })

    def _check_geo_blocking(self, name, cfg):
        geo = cfg.get("geo-pool", cfg.get("geo-blocking", cfg.get("global-acls", {}).get("geo-pool", "")))
        if not geo or (isinstance(geo, str) and geo.lower() in ("off", "disabled", "none", "")):
            self.findings.append({
                "id": "ACL-003",
                "title": "Geographic IP blocking not configured",
                "severity": "LOW",
                "category": "Access Control",
                "resource": name,
                "actual": "No geo-blocking",
                "expected": "Geo-blocking for high-risk countries",
                "recommendation": "Configure geo-blocking to restrict access from countries where your application has no legitimate users"
            })

    def _check_rate_limiting(self, name, rate, cfg):
        if not rate:
            rate_cfg = cfg.get("rate-control", cfg.get("rate-limiting", {}))
            if not rate_cfg or (isinstance(rate_cfg, dict) and not rate_cfg.get("status", "").lower() in ("on", "enabled")):
                self.findings.append({
                    "id": "ACL-005",
                    "title": "Rate limiting not configured",
                    "severity": "HIGH",
                    "category": "Access Control",
                    "resource": name,
                    "actual": "No rate limiting",
                    "expected": "Rate limiting enabled per client IP",
                    "recommendation": "Configure rate limiting to prevent abuse, credential stuffing, and application-layer DoS attacks"
                })
            return

        for rule in rate:
            max_req = rule.get("max-requests-per-second", rule.get("rate", 0))
            try:
                max_req = int(max_req)
            except (ValueError, TypeError):
                max_req = 0
            if max_req > 1000:
                self.findings.append({
                    "id": "ACL-006",
                    "title": f"Rate limit too high: {max_req} req/sec",
                    "severity": "MEDIUM",
                    "category": "Access Control",
                    "resource": name,
                    "actual": f"{max_req} requests/second",
                    "expected": "<= 1000 requests/second per client",
                    "recommendation": "Lower the rate limit threshold to an appropriate level for your application's expected traffic"
                })

    def _check_brute_force(self, name, cfg):
        bf = cfg.get("brute-force-prevention", cfg.get("login-protection", cfg.get("slow-client-attack", {})))
        if isinstance(bf, dict):
            enabled = bf.get("status", bf.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "ACL-007",
                    "title": "Brute-force prevention disabled",
                    "severity": "HIGH",
                    "category": "Access Control",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable brute-force prevention to protect login forms from credential stuffing attacks"
                })
            max_attempts = int(bf.get("max-attempts", bf.get("max-login-attempts", 0)))
            if max_attempts > 10:
                self.findings.append({
                    "id": "ACL-008",
                    "title": f"Brute-force threshold too high: {max_attempts} attempts",
                    "severity": "MEDIUM",
                    "category": "Access Control",
                    "resource": name,
                    "actual": f"{max_attempts} attempts before lockout",
                    "expected": "<= 10 attempts",
                    "recommendation": "Reduce max login attempts to 5-10 before triggering account lockout or CAPTCHA"
                })
        elif not bf:
            self.findings.append({
                "id": "ACL-007",
                "title": "Brute-force prevention not configured",
                "severity": "HIGH",
                "category": "Access Control",
                "resource": name,
                "actual": "Not configured",
                "expected": "Brute-force prevention enabled",
                "recommendation": "Configure brute-force prevention with lockout thresholds and penalty periods"
            })

    def _check_url_acls(self, name, cfg):
        url_acls = cfg.get("url-acls", cfg.get("url-access-control", []))
        if isinstance(url_acls, list):
            for acl in url_acls:
                url_pattern = acl.get("url", acl.get("url-match", ""))
                if isinstance(url_pattern, str) and url_pattern in ("/*", "*", "/"):
                    action = acl.get("action", "")
                    if isinstance(action, str) and action.lower() == "allow":
                        self.findings.append({
                            "id": "ACL-009",
                            "title": "Wildcard URL ACL allows all paths",
                            "severity": "MEDIUM",
                            "category": "Access Control",
                            "resource": name,
                            "actual": f"Allow all on {url_pattern}",
                            "expected": "Specific URL path restrictions",
                            "recommendation": "Restrict URL ACLs to specific paths rather than using wildcard allow rules"
                        })

    def _check_ip_reputation(self, name, cfg):
        ip_rep = cfg.get("ip-reputation", cfg.get("advanced-configuration", {}).get("ip-reputation", ""))
        if isinstance(ip_rep, str) and ip_rep.lower() in ("off", "disabled", "no", ""):
            self.findings.append({
                "id": "ACL-010",
                "title": "IP reputation filtering disabled",
                "severity": "MEDIUM",
                "category": "Access Control",
                "resource": name,
                "actual": "IP reputation disabled",
                "expected": "IP reputation filtering enabled",
                "recommendation": "Enable IP reputation filtering to block known malicious IPs, botnets, and Tor exit nodes"
            })

    def _check_trusted_hosts(self, name, cfg):
        trusted = cfg.get("trusted-hosts-group", cfg.get("trusted-hosts", ""))
        if not trusted or (isinstance(trusted, str) and trusted.lower() in ("none", "")):
            self.findings.append({
                "id": "ACL-011",
                "title": "No trusted hosts group configured",
                "severity": "INFO",
                "category": "Access Control",
                "resource": name,
                "actual": "No trusted hosts defined",
                "expected": "Trusted hosts group for management access",
                "recommendation": "Define trusted hosts groups to whitelist management and monitoring IP addresses"
            })

        xff = cfg.get("x-forwarded-for", cfg.get("trusted-proxy", ""))
        if isinstance(xff, str) and xff.lower() in ("off", "disabled", ""):
            self.findings.append({
                "id": "ACL-012",
                "title": "X-Forwarded-For header trust not configured",
                "severity": "LOW",
                "category": "Access Control",
                "resource": name,
                "actual": "XFF header not trusted",
                "expected": "XFF trusted from known proxy IPs",
                "recommendation": "Configure trusted proxy IPs for X-Forwarded-For header processing if behind a load balancer or CDN"
            })
