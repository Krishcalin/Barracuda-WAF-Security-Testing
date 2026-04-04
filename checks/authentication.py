"""Authentication and administrative access security checks."""

import logging
from utils.config_helper import safe_int, deep_get, extract_config

logger = logging.getLogger(__name__)


class AuthenticationChecker:
    """Assess admin authentication, password policy, MFA, session management,
    and LDAP/SAML/RADIUS integration security."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running authentication checks...")
        admin_cfg = self.api.get_admin_config()
        cfg = extract_config(admin_cfg) if isinstance(admin_cfg, dict) else {}

        self._check_default_credentials(cfg)
        self._check_password_policy(cfg)
        self._check_mfa(cfg)
        self._check_session_timeout(cfg)
        self._check_login_banner(cfg)
        self._check_admin_access_restriction(cfg)
        self._check_ldap_security(cfg)
        self._check_saml_config(cfg)
        self._check_role_based_access(cfg)
        self._check_api_access(cfg)
        self._check_account_lockout(cfg)
        self._check_audit_logging(cfg)

        return self.findings

    def _check_default_credentials(self, cfg):
        admin_users = cfg.get("admin-accounts", cfg.get("administrators", []))
        if isinstance(admin_users, list):
            for user in admin_users:
                username = user.get("username", user.get("name", ""))
                if isinstance(username, str) and username.lower() in ("admin", "administrator", "root"):
                    self.findings.append({
                        "id": "AUTH-001",
                        "title": f"Default admin account '{username}' still active",
                        "severity": "HIGH",
                        "category": "Authentication",
                        "resource": username,
                        "actual": f"Default account '{username}' exists",
                        "expected": "Renamed or disabled default accounts",
                        "recommendation": "Rename or disable default admin accounts and create named individual admin accounts",
                        "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'username':'<NEW_ADMIN>'}'''"
                    })

    def _check_password_policy(self, cfg):
        pwd_policy = cfg.get("password-policy", cfg.get("password-complexity", {}))
        if isinstance(pwd_policy, dict):
            min_len = safe_int(pwd_policy.get("min-length", pwd_policy.get("minimum-length", 0)))
            if min_len < 12:
                self.findings.append({
                    "id": "AUTH-002",
                    "title": f"Minimum password length too short: {min_len}",
                    "severity": "HIGH",
                    "category": "Authentication",
                    "resource": "Password Policy",
                    "actual": f"{min_len} characters" if min_len else "Not configured",
                    "expected": ">= 12 characters",
                    "recommendation": "Set minimum password length to 12 or more characters",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/password-policy -H 'Authorization: Basic <token>' -d \"{'min-length':'12'}'''"
                })
            complexity = pwd_policy.get("complexity", pwd_policy.get("require-complexity", ""))
            if isinstance(complexity, str) and complexity.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "AUTH-003",
                    "title": "Password complexity requirements disabled",
                    "severity": "HIGH",
                    "category": "Authentication",
                    "resource": "Password Policy",
                    "actual": "Complexity not required",
                    "expected": "Uppercase, lowercase, numbers, special characters required",
                    "recommendation": "Enable password complexity requirements (uppercase, lowercase, digits, special characters)",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/password-policy -H 'Authorization: Basic <token>' -d \"{'complexity':'on'}'''"
                })
            max_age = safe_int(pwd_policy.get("max-age", pwd_policy.get("expiry-days", 0)))
            if max_age == 0 or max_age > 90:
                self.findings.append({
                    "id": "AUTH-004",
                    "title": "Password expiry not enforced or too long",
                    "severity": "MEDIUM",
                    "category": "Authentication",
                    "resource": "Password Policy",
                    "actual": f"{max_age} days" if max_age else "No expiry",
                    "expected": "<= 90 days",
                    "recommendation": "Set password maximum age to 90 days or less",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/password-policy -H 'Authorization: Basic <token>' -d \"{'max-age':'90'}'''"
                })
            history = safe_int(pwd_policy.get("history", pwd_policy.get("password-history", 0)))
            if history < 5:
                self.findings.append({
                    "id": "AUTH-011",
                    "title": f"Password history too short: {history}",
                    "severity": "LOW",
                    "category": "Authentication",
                    "resource": "Password Policy",
                    "actual": f"{history} passwords remembered" if history else "No history",
                    "expected": ">= 5 passwords remembered",
                    "recommendation": "Set password history to remember at least 5 previous passwords to prevent reuse",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/account-lockout -H 'Authorization: Basic <token>' -d \"{'status':'enabled','max-attempts':'5'}'''"
                })
        else:
            self.findings.append({
                "id": "AUTH-002",
                "title": "Password policy not configured",
                "severity": "HIGH",
                "category": "Authentication",
                "resource": "Password Policy",
                "actual": "No password policy",
                "expected": "Strong password policy enforced",
                "recommendation": "Configure password policy with minimum length (12+), complexity, expiry (90 days), and history",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/password-policy -H 'Authorization: Basic <token>' -d \"{'min-length':'12'}'''"
            })

    def _check_mfa(self, cfg):
        mfa = cfg.get("mfa", cfg.get("two-factor-authentication", cfg.get("multi-factor", {})))
        if isinstance(mfa, dict):
            enabled = mfa.get("status", mfa.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "AUTH-005",
                    "title": "Multi-factor authentication disabled for admin access",
                    "severity": "CRITICAL",
                    "category": "Authentication",
                    "resource": "Admin MFA",
                    "actual": "MFA disabled",
                    "expected": "MFA enabled for all admin accounts",
                    "recommendation": "Enable MFA (TOTP, RADIUS, or certificate) for all administrative access",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/mfa -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''"
                })
        elif not mfa:
            self.findings.append({
                "id": "AUTH-005",
                "title": "Multi-factor authentication not configured",
                "severity": "CRITICAL",
                "category": "Authentication",
                "resource": "Admin MFA",
                "actual": "MFA not configured",
                "expected": "MFA enabled for all admin accounts",
                "recommendation": "Configure and enforce MFA for all administrative access to the WAF management interface",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/mfa -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''"
            })

    def _check_session_timeout(self, cfg):
        timeout = cfg.get("session-timeout", cfg.get("idle-timeout", cfg.get("management-session-timeout", 0)))
        try:
            timeout = int(timeout)
        except (ValueError, TypeError):
            timeout = 0
        if timeout == 0 or timeout > 900:
            self.findings.append({
                "id": "AUTH-006",
                "title": "Admin session timeout too long or not set",
                "severity": "MEDIUM",
                "category": "Authentication",
                "resource": "Session Management",
                "actual": f"{timeout} seconds" if timeout else "No timeout",
                "expected": "<= 900 seconds (15 minutes)",
                "recommendation": "Set admin session idle timeout to 15 minutes or less",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'session-timeout':'900'}'''"
            })

    def _check_login_banner(self, cfg):
        banner = cfg.get("login-banner", cfg.get("login-message", ""))
        if not banner or (isinstance(banner, str) and not banner.strip()):
            self.findings.append({
                "id": "AUTH-007",
                "title": "No login warning banner configured",
                "severity": "LOW",
                "category": "Authentication",
                "resource": "Login Banner",
                "actual": "No banner",
                "expected": "Legal warning banner displayed at login",
                "recommendation": "Configure a login banner with authorized-use-only warning for legal compliance",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'login-banner':'Authorized use only.'}'''"
            })

    def _check_admin_access_restriction(self, cfg):
        mgmt_acl = cfg.get("management-access-control", cfg.get("allowed-management-ips", ""))
        if not mgmt_acl or (isinstance(mgmt_acl, str) and mgmt_acl in ("any", "0.0.0.0/0", "*", "")):
            self.findings.append({
                "id": "AUTH-008",
                "title": "Admin management access not restricted by IP",
                "severity": "HIGH",
                "category": "Authentication",
                "resource": "Management Access",
                "actual": "Management accessible from any IP",
                "expected": "Management restricted to specific admin IPs/subnets",
                "recommendation": "Restrict management interface access to specific trusted IP addresses or subnets",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'management-access-control':'10.0.0.0/24'}'''"
            })

    def _check_ldap_security(self, cfg):
        ldap = cfg.get("ldap", cfg.get("ldap-configuration", {}))
        if isinstance(ldap, dict) and ldap:
            ssl = ldap.get("use-ssl", ldap.get("ldaps", ldap.get("encryption", "")))
            if isinstance(ssl, str) and ssl.lower() in ("off", "no", "disabled", "none", ""):
                self.findings.append({
                    "id": "AUTH-009",
                    "title": "LDAP connection not encrypted",
                    "severity": "HIGH",
                    "category": "Authentication",
                    "resource": "LDAP Integration",
                    "actual": "LDAP without SSL/TLS",
                    "expected": "LDAPS (port 636) or STARTTLS",
                    "recommendation": "Enable LDAPS or STARTTLS for LDAP connections to protect credentials in transit",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/ldap -H 'Authorization: Basic <token>' -d \"{'use-ssl':'on'}'''"
                })

    def _check_saml_config(self, cfg):
        saml = cfg.get("saml", cfg.get("saml-sso", {}))
        if isinstance(saml, dict) and saml:
            signed = saml.get("signed-assertions", saml.get("require-signed-response", ""))
            if isinstance(signed, str) and signed.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "AUTH-010",
                    "title": "SAML assertion signing not required",
                    "severity": "HIGH",
                    "category": "Authentication",
                    "resource": "SAML SSO",
                    "actual": "Unsigned assertions accepted",
                    "expected": "Signed SAML assertions required",
                    "recommendation": "Require signed SAML assertions to prevent authentication bypass via forged assertions",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/saml -H 'Authorization: Basic <token>' -d \"{'signed-assertions':'on'}'''"
                })

    def _check_role_based_access(self, cfg):
        rbac = cfg.get("roles", cfg.get("admin-roles", []))
        if isinstance(rbac, list) and len(rbac) <= 1:
            self.findings.append({
                "id": "AUTH-012",
                "title": "No role-based access control configured",
                "severity": "MEDIUM",
                "category": "Authentication",
                "resource": "RBAC",
                "actual": f"{len(rbac)} role(s) defined",
                "expected": "Multiple roles with least-privilege assignments",
                "recommendation": "Define granular admin roles (full admin, read-only, policy editor) following least-privilege principle",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'audit-log':'on'}'''"
            })

    def _check_api_access(self, cfg):
        api = cfg.get("api-access", cfg.get("rest-api", {}))
        if isinstance(api, dict):
            enabled = api.get("status", api.get("enabled", ""))
            acl = api.get("allowed-ips", api.get("access-control", ""))
            if isinstance(enabled, str) and enabled.lower() in ("on", "yes", "enabled"):
                if not acl or (isinstance(acl, str) and acl in ("any", "*", "0.0.0.0/0", "")):
                    self.findings.append({
                        "id": "AUTH-008",
                        "title": "REST API access not restricted by IP",
                        "severity": "HIGH",
                        "category": "Authentication",
                        "resource": "REST API",
                        "actual": "API accessible from any IP",
                        "expected": "API restricted to management IPs",
                        "recommendation": "Restrict REST API access to specific trusted IP addresses",
                        "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'management-access-control':'10.0.0.0/24'}'''"
                    })

    def _check_account_lockout(self, cfg):
        lockout = cfg.get("account-lockout", cfg.get("login-lockout", {}))
        if isinstance(lockout, dict):
            enabled = lockout.get("status", lockout.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "AUTH-011",
                    "title": "Admin account lockout disabled",
                    "severity": "HIGH",
                    "category": "Authentication",
                    "resource": "Account Lockout",
                    "actual": "Lockout disabled",
                    "expected": "Lockout after 5 failed attempts",
                    "recommendation": "Enable account lockout after 5 failed login attempts with a minimum 30-minute lockout period",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin/account-lockout -H 'Authorization: Basic <token>' -d \"{'status':'enabled','max-attempts':'5'}'''"
                })

    def _check_audit_logging(self, cfg):
        audit = cfg.get("audit-log", cfg.get("admin-audit-log", ""))
        if isinstance(audit, str) and audit.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "AUTH-012",
                "title": "Admin audit logging disabled",
                "severity": "HIGH",
                "category": "Authentication",
                "resource": "Audit Log",
                "actual": "Audit logging disabled",
                "expected": "Full admin action audit logging",
                "recommendation": "Enable audit logging for all administrative actions for accountability and forensics",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/admin -H 'Authorization: Basic <token>' -d \"{'audit-log':'on'}'''"
            })
