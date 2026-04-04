"""Content rules, URL rewriting, and redirect security checks."""

import logging
from utils.config_helper import safe_int, deep_get, extract_config

logger = logging.getLogger(__name__)


class ContentRulesChecker:
    """Assess content rules — URL rewriting, redirect security, response rewriting,
    header manipulation, and caching directives per service."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running content rules checks...")
        services = self.api.get_services()

        for svc in services:
            name = svc.get("name", svc.get("id", "unknown"))
            rules = self.api.get_content_rules(name)
            detail = self.api.get_service_detail(name)
            cfg = extract_config(detail, fallback=svc) if isinstance(detail, dict) else svc

            self._check_content_rules_exist(name, rules)
            self._check_open_redirects(name, rules, cfg)
            self._check_rewrite_security(name, rules, cfg)
            self._check_response_headers(name, cfg)
            self._check_security_headers(name, cfg)
            self._check_clickjacking_protection(name, cfg)
            self._check_content_type_options(name, cfg)
            self._check_referrer_policy(name, cfg)
            self._check_csp_header(name, cfg)
            self._check_permissions_policy(name, cfg)

        return self.findings

    def _check_content_rules_exist(self, name, rules):
        if not rules:
            self.findings.append({
                "id": "CR-001",
                "title": "No content rules configured",
                "severity": "INFO",
                "category": "Content Rules",
                "resource": name,
                "actual": "No content rules defined",
                "expected": "Content rules for URL routing and access control",
                "recommendation": "Consider configuring content rules to enforce URL-based routing and restrict access to sensitive paths",
                "remediation_cmd": "Configure content rules via WAF management console: WEBSITES > Content Rules"
            })

    def _check_open_redirects(self, name, rules, cfg):
        redirect_rules = cfg.get("redirect-rules", cfg.get("url-redirects", []))
        if isinstance(redirect_rules, list):
            for rule in redirect_rules:
                target = rule.get("redirect-url", rule.get("target", ""))
                condition = rule.get("condition", rule.get("match", ""))
                if isinstance(target, str) and ("$" in target or "{" in target):
                    if isinstance(condition, str) and (".*" in condition or "(.+)" in condition):
                        self.findings.append({
                            "id": "CR-002",
                            "title": "Potential open redirect in URL rewrite rule",
                            "severity": "HIGH",
                            "category": "Content Rules",
                            "resource": name,
                            "actual": f"Redirect target uses dynamic substitution: {target}",
                            "expected": "Redirect targets should be fixed URLs or validated domains",
                            "recommendation": "Avoid dynamic redirect targets derived from user input — use fixed destination URLs or validate against a whitelist of allowed domains",
                            "remediation_cmd": "Review and restrict redirect targets to fixed URLs via WAF management console"
                        })

        for rule in (rules if isinstance(rules, list) else []):
            url_match = rule.get("url-match", rule.get("url", ""))
            redirect = rule.get("redirect-url", rule.get("rewrite-to", ""))
            if isinstance(redirect, str) and redirect.startswith("http"):
                host_match = rule.get("host-match", "")
                if isinstance(host_match, str) and host_match in ("*", "", ".*"):
                    self.findings.append({
                        "id": "CR-002",
                        "title": f"External redirect with wildcard host match",
                        "severity": "MEDIUM",
                        "category": "Content Rules",
                        "resource": name,
                        "actual": f"Redirect to {redirect} for host '{host_match or '*'}'",
                        "expected": "Specific host matching for external redirects",
                        "recommendation": "Restrict host-match to specific domains when configuring external redirects",
                        "remediation_cmd": "Review and restrict redirect targets to fixed URLs via WAF management console"
                    })

    def _check_rewrite_security(self, name, rules, cfg):
        for rule in (rules if isinstance(rules, list) else []):
            rewrite = rule.get("rewrite-to", rule.get("url-rewrite", ""))
            if isinstance(rewrite, str):
                if "/../" in rewrite or "/.." in rewrite:
                    self.findings.append({
                        "id": "CR-003",
                        "title": "Path traversal pattern in URL rewrite rule",
                        "severity": "HIGH",
                        "category": "Content Rules",
                        "resource": name,
                        "actual": f"Rewrite target contains traversal: {rewrite}",
                        "expected": "No path traversal sequences in rewrite targets",
                        "recommendation": "Remove path traversal sequences (../) from URL rewrite rules to prevent directory escape",
                        "remediation_cmd": "Remove path traversal sequences from URL rewrite rules via WAF management console"
                    })

            mode = rule.get("mode", rule.get("rewrite-mode", ""))
            if isinstance(mode, str) and mode.lower() in ("passthrough", "transparent"):
                web_firewall = rule.get("web-firewall-policy", "")
                if not web_firewall or (isinstance(web_firewall, str) and web_firewall.lower() in ("none", "")):
                    self.findings.append({
                        "id": "CR-004",
                        "title": "Content rule in passthrough mode without WAF policy",
                        "severity": "HIGH",
                        "category": "Content Rules",
                        "resource": name,
                        "actual": f"Passthrough mode, no WAF policy on rule '{rule.get('name', 'unnamed')}'",
                        "expected": "WAF security policy assigned to all content rules",
                        "recommendation": "Assign a WAF security policy to content rules operating in passthrough mode to ensure traffic inspection",
                        "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/content-rules/<RULE> -H 'Authorization: Basic <token>' -d \"{'web-firewall-policy':'default-policy'}'''")
                    })

    def _check_response_headers(self, name, cfg):
        headers = cfg.get("response-headers", cfg.get("header-rewrite", {}))
        if isinstance(headers, dict):
            remove_server = headers.get("remove-headers", "")
            if isinstance(remove_server, str):
                sensitive = []
                for h in ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "Server"]:
                    if h.lower() not in remove_server.lower():
                        sensitive.append(h)
                if sensitive:
                    self.findings.append({
                        "id": "CR-005",
                        "title": f"Sensitive response headers not stripped: {', '.join(sensitive)}",
                        "severity": "MEDIUM",
                        "category": "Content Rules",
                        "resource": name,
                        "actual": f"Headers still exposed: {', '.join(sensitive)}",
                        "expected": "Remove X-Powered-By, X-AspNet-Version, Server headers",
                        "recommendation": "Configure response header removal for technology fingerprinting headers (X-Powered-By, X-AspNet-Version, Server)",
                        "remediation_cmd": "Configure response header removal: WEBSITES > Response Headers"
                    })

    def _check_security_headers(self, name, cfg):
        headers = cfg.get("response-headers", cfg.get("header-rewrite", cfg.get("insert-headers", {})))
        added = ""
        if isinstance(headers, dict):
            added = str(headers.get("add-headers", headers.get("insert-headers", "")))
        elif isinstance(headers, str):
            added = headers

        if "Strict-Transport-Security" not in added:
            hsts = cfg.get("hsts", cfg.get("strict-transport-security", {}))
            hsts_on = False
            if isinstance(hsts, dict):
                hsts_on = hsts.get("status", "").lower() in ("on", "enabled", "yes")
            if not hsts_on:
                self.findings.append({
                    "id": "CR-006",
                    "title": "Strict-Transport-Security header not configured",
                    "severity": "MEDIUM",
                    "category": "Content Rules",
                    "resource": name,
                    "actual": "HSTS header not present in responses",
                    "expected": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
                    "recommendation": "Add HSTS header via response header insertion or enable the built-in HSTS feature",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/hsts -H 'Authorization: Basic <token>' -d \"{'status':'on','max-age':'31536000'}'''")
                })

    def _check_clickjacking_protection(self, name, cfg):
        headers = cfg.get("response-headers", cfg.get("insert-headers", {}))
        added = str(headers) if headers else ""
        if "X-Frame-Options" not in added and "frame-ancestors" not in added.lower():
            self.findings.append({
                "id": "CR-007",
                "title": "Clickjacking protection (X-Frame-Options) not configured",
                "severity": "MEDIUM",
                "category": "Content Rules",
                "resource": name,
                "actual": "No X-Frame-Options or CSP frame-ancestors header",
                "expected": "X-Frame-Options: DENY or SAMEORIGIN",
                "recommendation": "Add X-Frame-Options header (DENY or SAMEORIGIN) or CSP frame-ancestors directive to prevent clickjacking",
                "remediation_cmd": "Add X-Frame-Options header: WEBSITES > Response Headers > Insert Header"
            })

    def _check_content_type_options(self, name, cfg):
        headers = cfg.get("response-headers", cfg.get("insert-headers", {}))
        added = str(headers) if headers else ""
        if "X-Content-Type-Options" not in added:
            self.findings.append({
                "id": "CR-008",
                "title": "X-Content-Type-Options: nosniff not configured",
                "severity": "LOW",
                "category": "Content Rules",
                "resource": name,
                "actual": "No X-Content-Type-Options header",
                "expected": "X-Content-Type-Options: nosniff",
                "recommendation": "Add X-Content-Type-Options: nosniff header to prevent MIME type sniffing attacks",
                "remediation_cmd": "Add X-Content-Type-Options: nosniff via: WEBSITES > Response Headers"
            })

    def _check_referrer_policy(self, name, cfg):
        headers = cfg.get("response-headers", cfg.get("insert-headers", {}))
        added = str(headers) if headers else ""
        if "Referrer-Policy" not in added:
            self.findings.append({
                "id": "CR-009",
                "title": "Referrer-Policy header not configured",
                "severity": "LOW",
                "category": "Content Rules",
                "resource": name,
                "actual": "No Referrer-Policy header",
                "expected": "Referrer-Policy: strict-origin-when-cross-origin",
                "recommendation": "Add Referrer-Policy header to control referrer information leakage to third-party sites",
                "remediation_cmd": "Add Referrer-Policy: strict-origin-when-cross-origin via: WEBSITES > Response Headers"
            })

    def _check_csp_header(self, name, cfg):
        headers = cfg.get("response-headers", cfg.get("insert-headers", {}))
        added = str(headers) if headers else ""
        if "Content-Security-Policy" not in added:
            self.findings.append({
                "id": "CR-010",
                "title": "Content-Security-Policy (CSP) header not configured",
                "severity": "MEDIUM",
                "category": "Content Rules",
                "resource": name,
                "actual": "No CSP header",
                "expected": "Content-Security-Policy with restrictive directives",
                "recommendation": "Configure Content-Security-Policy header to mitigate XSS, data injection, and clickjacking attacks",
                "remediation_cmd": "Add Content-Security-Policy header via: WEBSITES > Response Headers"
            })

    def _check_permissions_policy(self, name, cfg):
        headers = cfg.get("response-headers", cfg.get("insert-headers", {}))
        added = str(headers) if headers else ""
        if "Permissions-Policy" not in added and "Feature-Policy" not in added:
            self.findings.append({
                "id": "CR-011",
                "title": "Permissions-Policy header not configured",
                "severity": "LOW",
                "category": "Content Rules",
                "resource": name,
                "actual": "No Permissions-Policy header",
                "expected": "Permissions-Policy restricting camera, microphone, geolocation",
                "recommendation": "Add Permissions-Policy header to restrict browser features (camera, microphone, geolocation) for defense in depth",
                "remediation_cmd": "Add Permissions-Policy header via: WEBSITES > Response Headers"
            })
