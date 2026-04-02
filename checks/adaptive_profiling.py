"""Adaptive profiling and learning mode security checks."""

import logging

logger = logging.getLogger(__name__)


class AdaptiveProfilingChecker:
    """Assess adaptive profiling — learning mode status, URL profiles,
    parameter profiles, profile enforcement, and exception handling."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running adaptive profiling checks...")
        services = self.api.get_services()
        policies = self.api.get_security_policies()

        for svc in services:
            name = svc.get("name", svc.get("id", "unknown"))
            detail = self.api.get_service_detail(name)
            cfg = detail.get("data", detail) if isinstance(detail, dict) else svc
            self._check_adaptive_profiling_status(name, cfg)
            self._check_learning_mode(name, cfg)
            self._check_trusted_hosts_learning(name, cfg)

        for policy in policies:
            pname = policy.get("name", policy.get("id", "unknown"))
            detail = self.api.get_security_policy(pname) if isinstance(pname, str) else policy
            pcfg = detail.get("data", detail) if isinstance(detail, dict) else policy
            self._check_url_profiles(pname, pcfg)
            self._check_parameter_profiles(pname, pcfg)
            self._check_profiling_enforcement(pname, pcfg)
            self._check_positive_security_model(pname, pcfg)
            self._check_profile_stale(pname, pcfg)

        return self.findings

    def _check_adaptive_profiling_status(self, name, cfg):
        profiling = cfg.get("adaptive-profiling", cfg.get("learning-mode", {}))
        if isinstance(profiling, dict):
            status = profiling.get("status", profiling.get("enabled", ""))
            if isinstance(status, str) and status.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "AP-001",
                    "title": "Adaptive profiling disabled",
                    "severity": "MEDIUM",
                    "category": "Adaptive Profiling",
                    "resource": name,
                    "actual": "Adaptive profiling disabled",
                    "expected": "Adaptive profiling enabled for traffic learning",
                    "recommendation": "Enable adaptive profiling to learn legitimate traffic patterns and build URL/parameter profiles for positive security enforcement",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/adaptive-profiling -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })
        elif not profiling:
            self.findings.append({
                "id": "AP-001",
                "title": "Adaptive profiling not configured",
                "severity": "MEDIUM",
                "category": "Adaptive Profiling",
                "resource": name,
                "actual": "Not configured",
                "expected": "Adaptive profiling enabled",
                "recommendation": "Configure adaptive profiling to automatically learn application URL and parameter patterns",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/adaptive-profiling -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
            })

    def _check_learning_mode(self, name, cfg):
        profiling = cfg.get("adaptive-profiling", cfg.get("learning-mode", {}))
        if isinstance(profiling, dict):
            mode = profiling.get("mode", profiling.get("learning-status", ""))
            if isinstance(mode, str) and mode.lower() in ("active", "learning", "on"):
                duration = profiling.get("learning-duration", profiling.get("duration-days", 0))
                try:
                    duration = int(duration)
                except (ValueError, TypeError):
                    duration = 0
                if duration > 30:
                    self.findings.append({
                        "id": "AP-002",
                        "title": f"Learning mode active for extended period ({duration} days)",
                        "severity": "HIGH",
                        "category": "Adaptive Profiling",
                        "resource": name,
                        "actual": f"Learning mode active, {duration} days configured",
                        "expected": "Learning period <= 30 days before switching to enforcement",
                        "recommendation": "Review and finalize learned profiles — extended learning mode delays enforcement of positive security rules, leaving the WAF in a permissive state",
                        "remediation_cmd": "Review learned profiles via WAF management console: WEBSITES > Adaptive Profiling"
                    })
                else:
                    self.findings.append({
                        "id": "AP-002",
                        "title": "Learning mode currently active",
                        "severity": "INFO",
                        "category": "Adaptive Profiling",
                        "resource": name,
                        "actual": f"Learning mode active ({duration} days)" if duration else "Learning mode active",
                        "expected": "Transition to enforcement after learning completes",
                        "recommendation": "Monitor learning progress and transition to enforcement mode once sufficient traffic patterns have been captured",
                        "remediation_cmd": "Review learned profiles via WAF management console: WEBSITES > Adaptive Profiling"
                    })

    def _check_trusted_hosts_learning(self, name, cfg):
        profiling = cfg.get("adaptive-profiling", cfg.get("learning-mode", {}))
        if isinstance(profiling, dict):
            trusted = profiling.get("trusted-hosts-only", profiling.get("learn-from-trusted", ""))
            if isinstance(trusted, str) and trusted.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "AP-003",
                    "title": "Learning from untrusted hosts enabled",
                    "severity": "HIGH",
                    "category": "Adaptive Profiling",
                    "resource": name,
                    "actual": "Learning from all traffic sources",
                    "expected": "Learning restricted to trusted hosts only",
                    "recommendation": "Restrict adaptive profiling to learn only from trusted host IPs to prevent attackers from poisoning the learned profiles",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/adaptive-profiling -H 'Authorization: Basic <token>' -d \"{'trusted-hosts-only':'on'}'''")
                })

    def _check_url_profiles(self, name, cfg):
        url_profiles = cfg.get("url-profiles", cfg.get("url-profile", {}))
        if isinstance(url_profiles, dict):
            status = url_profiles.get("status", url_profiles.get("enabled", ""))
            if isinstance(status, str) and status.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "AP-004",
                    "title": "URL profile enforcement disabled",
                    "severity": "MEDIUM",
                    "category": "Adaptive Profiling",
                    "resource": name,
                    "actual": "URL profiles not enforced",
                    "expected": "URL profiles enforced to restrict access to known paths",
                    "recommendation": "Enable URL profile enforcement to restrict access to only learned/approved URL paths",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/url-profiles -H 'Authorization: Basic <token>' -d \"{'status':'on'}'''")
                })
            strict = url_profiles.get("strict-mode", url_profiles.get("strict-url-check", ""))
            if isinstance(strict, str) and strict.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "AP-005",
                    "title": "Strict URL matching disabled",
                    "severity": "LOW",
                    "category": "Adaptive Profiling",
                    "resource": name,
                    "actual": "Lenient URL matching",
                    "expected": "Strict URL matching for tighter security",
                    "recommendation": "Enable strict URL matching to block requests to URLs not in the learned profile",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/url-profiles -H 'Authorization: Basic <token>' -d \"{'strict-mode':'on'}'''")
                })

    def _check_parameter_profiles(self, name, cfg):
        param_profiles = cfg.get("parameter-profiles", cfg.get("parameter-profile", {}))
        if isinstance(param_profiles, dict):
            status = param_profiles.get("status", param_profiles.get("enabled", ""))
            if isinstance(status, str) and status.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "AP-006",
                    "title": "Parameter profile enforcement disabled",
                    "severity": "MEDIUM",
                    "category": "Adaptive Profiling",
                    "resource": name,
                    "actual": "Parameter profiles not enforced",
                    "expected": "Parameter profiles enforced with type/length constraints",
                    "recommendation": "Enable parameter profile enforcement to validate parameter names, types, and lengths against learned patterns",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/parameter-profiles -H 'Authorization: Basic <token>' -d \"{'status':'on'}'''")
                })
            max_val = param_profiles.get("max-value-length", param_profiles.get("max-parameter-value", 0))
            try:
                max_val = int(max_val)
            except (ValueError, TypeError):
                max_val = 0
            if max_val == 0 or max_val > 65536:
                self.findings.append({
                    "id": "AP-007",
                    "title": "Parameter max value length not constrained",
                    "severity": "MEDIUM",
                    "category": "Adaptive Profiling",
                    "resource": name,
                    "actual": str(max_val) if max_val else "Unlimited",
                    "expected": "Appropriate limits based on learned patterns",
                    "recommendation": "Set parameter max value length based on learned profiles to detect buffer overflow and injection attempts",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/security-policies/" + name + "/parameter-profiles -H 'Authorization: Basic <token>' -d \"{'max-value-length':'4096'}'''")
                })

    def _check_profiling_enforcement(self, name, cfg):
        enforcement = cfg.get("profiling-enforcement", cfg.get("adaptive-profiling", {}).get("enforcement", ""))
        if isinstance(enforcement, str) and enforcement.lower() in ("passive", "log-only", "monitor"):
            self.findings.append({
                "id": "AP-008",
                "title": "Adaptive profiling in passive/log-only mode",
                "severity": "MEDIUM",
                "category": "Adaptive Profiling",
                "resource": name,
                "actual": f"Enforcement mode: {enforcement}",
                "expected": "Active enforcement (block violations)",
                "recommendation": "Switch adaptive profiling from passive/log-only to active enforcement to block requests that violate learned profiles",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/adaptive-profiling -H 'Authorization: Basic <token>' -d \"{'enforcement':'active'}'''")
            })

    def _check_positive_security_model(self, name, cfg):
        positive = cfg.get("positive-security", cfg.get("allow-known-only", ""))
        if isinstance(positive, str) and positive.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "AP-009",
                "title": "Positive security model not enabled",
                "severity": "LOW",
                "category": "Adaptive Profiling",
                "resource": name,
                "actual": "Negative security model only (signature-based)",
                "expected": "Positive + negative security model",
                "recommendation": "Consider enabling positive security model (allow-list) in addition to signature-based detection for defense in depth",
                "remediation_cmd": "Enable positive security model via WAF management console: SECURITY POLICIES > Positive Security"
            })

    def _check_profile_stale(self, name, cfg):
        profiling = cfg.get("adaptive-profiling", cfg.get("learning-mode", {}))
        if isinstance(profiling, dict):
            last_update = profiling.get("last-profile-update", profiling.get("profile-updated", ""))
            if not last_update:
                auto_refresh = profiling.get("auto-refresh", profiling.get("auto-update-profiles", ""))
                if isinstance(auto_refresh, str) and auto_refresh.lower() in ("off", "no", "disabled", ""):
                    self.findings.append({
                        "id": "AP-010",
                        "title": "Profile auto-refresh disabled",
                        "severity": "LOW",
                        "category": "Adaptive Profiling",
                        "resource": name,
                        "actual": "Auto-refresh disabled",
                        "expected": "Periodic profile refresh to capture application changes",
                        "recommendation": "Enable profile auto-refresh or schedule periodic re-learning to capture application changes over time",
                        "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/adaptive-profiling -H 'Authorization: Basic <token>' -d \"{'auto-refresh':'on'}'''")
                    })
