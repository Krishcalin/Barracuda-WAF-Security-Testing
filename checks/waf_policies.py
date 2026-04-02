"""WAF policy configuration security checks."""

import logging

logger = logging.getLogger(__name__)


class WafPoliciesChecker:
    """Assess WAF security policy configuration — attack actions, request limits,
    cookie security, parameter protection, URL normalization, data theft prevention."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running WAF policy checks...")
        policies = self.api.get_security_policies()
        if not policies:
            self.findings.append({
                "id": "WAF-POL-001",
                "title": "No WAF security policies found",
                "severity": "CRITICAL",
                "category": "WAF Policy",
                "resource": "Global",
                "actual": "No policies configured",
                "expected": "At least one security policy active",
                "recommendation": "Create and assign WAF security policies to all virtual services",
                "remediation_cmd": "Create a security policy via WAF management console: SECURITY POLICIES > Create Policy"
            })
            return self.findings

        for policy in policies:
            name = policy.get("name", policy.get("id", "unknown"))
            detail = self.api.get_security_policy(name) if isinstance(name, str) else policy
            cfg = detail.get("data", detail) if isinstance(detail, dict) else policy
            self._check_attack_action(name, cfg)
            self._check_cloaking(name, cfg)
            self._check_request_limits(name, cfg)
            self._check_cookie_security(name, cfg)
            self._check_parameter_protection(name, cfg)
            self._check_url_normalization(name, cfg)
            self._check_data_theft_protection(name, cfg)
            self._check_outbound_response(name, cfg)
            self._check_url_protection(name, cfg)
            self._check_allowed_methods(name, cfg)
            self._check_input_validation(name, cfg)
            self._check_json_security(name, cfg)
            self._check_xml_firewall(name, cfg)

        return self.findings

    def _check_attack_action(self, name, cfg):
        action = cfg.get("attack-action", cfg.get("web-firewall-policy", {}).get("attack-action", ""))
        if action and action.lower() not in ("deny-and-log", "deny"):
            self.findings.append({
                "id": "WAF-POL-002",
                "title": "Attack action not set to Deny and Log",
                "severity": "HIGH",
                "category": "WAF Policy",
                "resource": name,
                "actual": action,
                "expected": "deny-and-log",
                "recommendation": "Set attack action to 'Deny and Log' to block attacks while retaining audit trail",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + " -H 'Authorization: Basic <token>' -d \"{'attack-action':'deny-and-log'}'''")
            })

    def _check_cloaking(self, name, cfg):
        cloaking = cfg.get("cloaking", cfg.get("web-firewall-policy", {}).get("cloaking", ""))
        if isinstance(cloaking, str) and cloaking.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "WAF-POL-003",
                "title": "Response cloaking disabled",
                "severity": "MEDIUM",
                "category": "WAF Policy",
                "resource": name,
                "actual": cloaking or "disabled",
                "expected": "Enabled",
                "recommendation": "Enable response cloaking to suppress server version headers and error details from reaching clients",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + " -H 'Authorization: Basic <token>' -d \"{'cloaking':'on'}'''")
            })

    def _check_request_limits(self, name, cfg):
        limits = cfg.get("request-limits", cfg.get("web-firewall-policy", {}).get("request-limits", {}))
        if isinstance(limits, dict):
            max_url = int(limits.get("max-url-length", 0))
            if max_url == 0 or max_url > 4096:
                self.findings.append({
                    "id": "WAF-POL-004",
                    "title": "Max URL length not restricted",
                    "severity": "MEDIUM",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": str(max_url) if max_url else "Unlimited",
                    "expected": "<=4096",
                    "recommendation": "Set max URL length to 4096 or less to prevent buffer overflow and path traversal attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/request-limits -H 'Authorization: Basic <token>' -d \"{'max-url-length':'4096'}'''")
                })
            max_header = int(limits.get("max-header-value-length", 0))
            if max_header == 0 or max_header > 8192:
                self.findings.append({
                    "id": "WAF-POL-005",
                    "title": "Max header value length not restricted",
                    "severity": "MEDIUM",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": str(max_header) if max_header else "Unlimited",
                    "expected": "<=8192",
                    "recommendation": "Set max header value length to 8192 or less to prevent header injection attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/request-limits -H 'Authorization: Basic <token>' -d \"{'max-header-value-length':'8192'}'''")
                })
            max_body = int(limits.get("max-request-length", 0))
            if max_body == 0 or max_body > 65536:
                self.findings.append({
                    "id": "WAF-POL-006",
                    "title": "Max request body length not restricted",
                    "severity": "LOW",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": str(max_body) if max_body else "Unlimited",
                    "expected": "<=65536",
                    "recommendation": "Set max request body length to limit large payload attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/request-limits -H 'Authorization: Basic <token>' -d \"{'max-request-length':'65536'}'''")
                })
            max_params = int(limits.get("max-number-of-parameters", 0))
            if max_params == 0 or max_params > 256:
                self.findings.append({
                    "id": "WAF-POL-007",
                    "title": "Max number of parameters not restricted",
                    "severity": "MEDIUM",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": str(max_params) if max_params else "Unlimited",
                    "expected": "<=256",
                    "recommendation": "Limit the number of request parameters to prevent parameter pollution and hash collision attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/request-limits -H 'Authorization: Basic <token>' -d \"{'max-number-of-parameters':'256'}'''")
                })

    def _check_cookie_security(self, name, cfg):
        cookies = cfg.get("cookie-security", cfg.get("web-firewall-policy", {}).get("cookie-security", {}))
        if isinstance(cookies, dict):
            tamper = cookies.get("tamper-proof-mode", "")
            if isinstance(tamper, str) and tamper.lower() in ("off", "none", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-008",
                    "title": "Cookie tamper protection disabled",
                    "severity": "HIGH",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": tamper or "disabled",
                    "expected": "Signed or Encrypted",
                    "recommendation": "Enable cookie tamper-proof mode (signed or encrypted) to prevent session manipulation",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/cookie-security -H 'Authorization: Basic <token>' -d \"{'tamper-proof-mode':'signed'}'''")
                })
            secure = cookies.get("secure-cookie", cookies.get("add-secure-flag", ""))
            if isinstance(secure, str) and secure.lower() in ("no", "off", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-009",
                    "title": "Secure flag not set on cookies",
                    "severity": "MEDIUM",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "Secure flag disabled",
                    "expected": "Secure flag enabled",
                    "recommendation": "Enable the Secure flag on cookies to prevent transmission over unencrypted connections",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/cookie-security -H 'Authorization: Basic <token>' -d \"{'secure-cookie':'yes'}'''")
                })
            httponly = cookies.get("http-only", "")
            if isinstance(httponly, str) and httponly.lower() in ("no", "off", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-010",
                    "title": "HttpOnly flag not set on cookies",
                    "severity": "MEDIUM",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "HttpOnly disabled",
                    "expected": "HttpOnly enabled",
                    "recommendation": "Enable HttpOnly flag to prevent client-side JavaScript from accessing session cookies",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/cookie-security -H 'Authorization: Basic <token>' -d \"{'http-only':'yes'}'''")
                })

    def _check_parameter_protection(self, name, cfg):
        param = cfg.get("parameter-protection", cfg.get("web-firewall-policy", {}).get("parameter-protection", {}))
        if isinstance(param, dict):
            sql = param.get("sql-injection", param.get("sql-injection-check", ""))
            if isinstance(sql, str) and sql.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-011",
                    "title": "SQL injection protection disabled",
                    "severity": "CRITICAL",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable SQL injection protection to block SQL injection attacks in request parameters",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/parameter-protection -H 'Authorization: Basic <token>' -d \"{'sql-injection':'on'}'''")
                })
            xss = param.get("cross-site-scripting", param.get("xss-check", ""))
            if isinstance(xss, str) and xss.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-012",
                    "title": "Cross-site scripting protection disabled",
                    "severity": "CRITICAL",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable XSS protection to block cross-site scripting attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/parameter-protection -H 'Authorization: Basic <token>' -d \"{'cross-site-scripting':'on'}'''")
                })
            cmd = param.get("os-command-injection", param.get("command-injection", ""))
            if isinstance(cmd, str) and cmd.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-013",
                    "title": "OS command injection protection disabled",
                    "severity": "CRITICAL",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable OS command injection protection to prevent command execution via web parameters",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/parameter-protection -H 'Authorization: Basic <token>' -d \"{'os-command-injection':'on'}'''")
                })

    def _check_url_normalization(self, name, cfg):
        norm = cfg.get("url-normalization", cfg.get("web-firewall-policy", {}).get("url-normalization", {}))
        if isinstance(norm, dict):
            double_decode = norm.get("double-decoding", norm.get("detect-double-encoding", ""))
            if isinstance(double_decode, str) and double_decode.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-014",
                    "title": "Double-decoding detection disabled",
                    "severity": "HIGH",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable double-decoding detection to catch URL obfuscation bypass attempts",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/url-normalization -H 'Authorization: Basic <token>' -d \"{'double-decoding':'on'}'''")
                })
            path_trav = norm.get("path-traversal", norm.get("detect-path-traversal", ""))
            if isinstance(path_trav, str) and path_trav.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-015",
                    "title": "Path traversal detection disabled",
                    "severity": "HIGH",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable path traversal detection to block directory traversal (../) attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/url-normalization -H 'Authorization: Basic <token>' -d \"{'path-traversal':'on'}'''")
                })

    def _check_data_theft_protection(self, name, cfg):
        dtp = cfg.get("data-theft-protection", cfg.get("web-firewall-policy", {}).get("data-theft-protection", {}))
        if isinstance(dtp, dict):
            cc = dtp.get("credit-card-number", dtp.get("credit-cards", ""))
            if isinstance(cc, str) and cc.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-016",
                    "title": "Credit card number masking disabled",
                    "severity": "HIGH",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable credit card number masking in responses to prevent PCI data leakage",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/data-theft-protection -H 'Authorization: Basic <token>' -d \"{'credit-card-number':'on'}'''")
                })
            ssn = dtp.get("social-security-number", dtp.get("ssn", ""))
            if isinstance(ssn, str) and ssn.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-017",
                    "title": "SSN masking disabled in responses",
                    "severity": "HIGH",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable Social Security Number masking in outbound responses to prevent PII data leakage",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/data-theft-protection -H 'Authorization: Basic <token>' -d \"{'social-security-number':'on'}'''")
                })
            custom = dtp.get("custom-pattern", "")
            if not custom:
                self.findings.append({
                    "id": "WAF-POL-018",
                    "title": "No custom data theft patterns configured",
                    "severity": "LOW",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "No custom patterns",
                    "expected": "Custom patterns for sensitive data",
                    "recommendation": "Define custom regex patterns for organization-specific sensitive data (employee IDs, internal codes)",
                    "remediation_cmd": "Configure custom data theft patterns via WAF management console or REST API"
                })

    def _check_outbound_response(self, name, cfg):
        resp_body = cfg.get("response-body-rewrite", cfg.get("web-firewall-policy", {}).get("response-body-rewrite", ""))
        server_header = cfg.get("suppress-return-codes", cfg.get("web-firewall-policy", {}).get("suppress-return-codes", ""))
        if isinstance(server_header, str) and server_header.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "WAF-POL-019",
                "title": "Server error code suppression disabled",
                "severity": "MEDIUM",
                "category": "WAF Policy",
                "resource": name,
                "actual": "Disabled",
                "expected": "Enabled",
                "recommendation": "Enable return code suppression to hide internal error codes (500, 503) from external users",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + " -H 'Authorization: Basic <token>' -d \"{'suppress-return-codes':'on'}'''")
            })

    def _check_url_protection(self, name, cfg):
        url_prot = cfg.get("url-protection", cfg.get("web-firewall-policy", {}).get("url-protection", {}))
        if isinstance(url_prot, dict):
            allowed_methods = url_prot.get("allowed-methods", "")
            if isinstance(allowed_methods, str) and "TRACE" in allowed_methods.upper():
                self.findings.append({
                    "id": "WAF-POL-020",
                    "title": "HTTP TRACE method allowed",
                    "severity": "MEDIUM",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "TRACE method permitted",
                    "expected": "TRACE method blocked",
                    "recommendation": "Block HTTP TRACE method to prevent cross-site tracing (XST) attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/url-protection -H 'Authorization: Basic <token>' -d \"{'allowed-methods':'GET POST HEAD'}'''")
                })

    def _check_allowed_methods(self, name, cfg):
        methods = cfg.get("allowed-methods", cfg.get("web-firewall-policy", {}).get("allowed-methods", ""))
        if isinstance(methods, str):
            dangerous = [m for m in ["DELETE", "PUT", "PATCH"] if m in methods.upper()]
            if dangerous:
                self.findings.append({
                    "id": "WAF-POL-021",
                    "title": f"Potentially dangerous HTTP methods allowed: {', '.join(dangerous)}",
                    "severity": "LOW",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": methods,
                    "expected": "Only required methods (GET, POST, HEAD)",
                    "recommendation": "Restrict allowed HTTP methods to only those required by the application",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + " -H 'Authorization: Basic <token>' -d \"{'allowed-methods':'GET POST HEAD'}'''")
                })

    def _check_input_validation(self, name, cfg):
        validation = cfg.get("input-validation", cfg.get("web-firewall-policy", {}).get("input-validation", {}))
        if isinstance(validation, dict):
            charset = validation.get("allowed-content-types", "")
            if isinstance(charset, str) and not charset.strip():
                self.findings.append({
                    "id": "WAF-POL-022",
                    "title": "Allowed content types not restricted",
                    "severity": "MEDIUM",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "All content types allowed",
                    "expected": "Only required content types (application/json, application/x-www-form-urlencoded, multipart/form-data)",
                    "recommendation": "Restrict allowed content types to prevent content-type-based attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/input-validation -H 'Authorization: Basic <token>' -d \"{'allowed-content-types':'application/json application/x-www-form-urlencoded'}'''")
                })

    def _check_json_security(self, name, cfg):
        json_sec = cfg.get("json-security", cfg.get("web-firewall-policy", {}).get("json-security", {}))
        if isinstance(json_sec, dict):
            enabled = json_sec.get("status", json_sec.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-023",
                    "title": "JSON security validation disabled",
                    "severity": "HIGH",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Enabled",
                    "recommendation": "Enable JSON security to validate JSON request bodies and prevent JSON injection attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/json-security -H 'Authorization: Basic <token>' -d \"{'status':'on'}'''")
                })
            max_depth = int(json_sec.get("max-depth", 0))
            if max_depth == 0 or max_depth > 64:
                self.findings.append({
                    "id": "WAF-POL-024",
                    "title": "JSON max nesting depth not limited",
                    "severity": "MEDIUM",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": str(max_depth) if max_depth else "Unlimited",
                    "expected": "<=64",
                    "recommendation": "Set JSON max nesting depth to prevent deeply nested payload DoS attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/json-security -H 'Authorization: Basic <token>' -d \"{'max-depth':'64'}'''")
                })

    def _check_xml_firewall(self, name, cfg):
        xml_fw = cfg.get("xml-firewall", cfg.get("web-firewall-policy", {}).get("xml-firewall", {}))
        if isinstance(xml_fw, dict):
            xxe = xml_fw.get("disable-external-entities", xml_fw.get("xxe-protection", ""))
            if isinstance(xxe, str) and xxe.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "WAF-POL-025",
                    "title": "XML External Entity (XXE) protection disabled",
                    "severity": "CRITICAL",
                    "category": "WAF Policy",
                    "resource": name,
                    "actual": "External entities allowed",
                    "expected": "External entities disabled",
                    "recommendation": "Disable XML external entities to prevent XXE injection attacks (OWASP A05)",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/xml-firewall -H 'Authorization: Basic <token>' -d \"{'disable-external-entities':'on'}'''")
                })
