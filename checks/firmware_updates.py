"""Firmware and update security checks."""

import logging

logger = logging.getLogger(__name__)

KNOWN_EOL_VERSIONS = {
    "7.": "7.x",
    "8.": "8.x",
    "9.": "9.x",
    "10.": "10.x",
    "11.": "11.x",
}

MINIMUM_RECOMMENDED_VERSION = "12.0"


class FirmwareUpdatesChecker:
    """Assess firmware version, EOL status, security patches, and
    energize update subscription."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running firmware and update checks...")
        sys_info = self.api.get_system_info()
        cfg = sys_info.get("data", sys_info) if isinstance(sys_info, dict) else {}

        self._check_firmware_version(cfg)
        self._check_eol_status(cfg)
        self._check_energize_subscription(cfg)
        self._check_auto_updates(cfg)
        self._check_attack_definitions(cfg)

        return self.findings

    def _check_firmware_version(self, cfg):
        version = cfg.get("firmware-version", cfg.get("version", cfg.get("system-version", "")))
        if not version:
            self.findings.append({
                "id": "FW-001",
                "title": "Unable to determine firmware version",
                "severity": "MEDIUM",
                "category": "Firmware & Updates",
                "resource": "System",
                "actual": "Version unknown",
                "expected": f"Firmware >= {MINIMUM_RECOMMENDED_VERSION}",
                "recommendation": "Verify firmware version manually and update to the latest stable release",
                "remediation_cmd": "Download latest firmware from Barracuda Cloud Control: ADVANCED > Firmware Update"
            })
            return

        version_str = str(version)
        try:
            major_minor = version_str.split(".")
            major = int(major_minor[0])
            if major < int(MINIMUM_RECOMMENDED_VERSION.split(".")[0]):
                self.findings.append({
                    "id": "FW-001",
                    "title": f"Outdated firmware version: {version_str}",
                    "severity": "HIGH",
                    "category": "Firmware & Updates",
                    "resource": "System",
                    "actual": f"Version {version_str}",
                    "expected": f">= {MINIMUM_RECOMMENDED_VERSION}",
                    "recommendation": f"Upgrade firmware to version {MINIMUM_RECOMMENDED_VERSION} or later for latest security patches and features",
                    "remediation_cmd": "Download latest firmware from Barracuda Cloud Control: ADVANCED > Firmware Update"
                })
        except (ValueError, IndexError):
            self.findings.append({
                "id": "FW-001",
                "title": f"Unrecognized firmware version format: {version_str}",
                "severity": "LOW",
                "category": "Firmware & Updates",
                "resource": "System",
                "actual": version_str,
                "expected": "Standard version format",
                "recommendation": "Verify the firmware version and ensure it is supported and up to date",
                "remediation_cmd": "Download latest firmware from Barracuda Cloud Control: ADVANCED > Firmware Update"
            })

    def _check_eol_status(self, cfg):
        version = str(cfg.get("firmware-version", cfg.get("version", "")))
        model = cfg.get("model", cfg.get("product-model", ""))

        for prefix, family in KNOWN_EOL_VERSIONS.items():
            if version.startswith(prefix):
                self.findings.append({
                    "id": "FW-002",
                    "title": f"Firmware {family} family has reached end of life",
                    "severity": "CRITICAL",
                    "category": "Firmware & Updates",
                    "resource": "System",
                    "actual": f"Version {version} (EOL family {family})",
                    "expected": "Supported firmware version",
                    "recommendation": f"Upgrade from EOL firmware {family} immediately — no security patches are available for EOL versions",
                    "remediation_cmd": "Upgrade from EOL firmware immediately via: ADVANCED > Firmware Update"
                })
                break

    def _check_energize_subscription(self, cfg):
        sub = cfg.get("energize-updates", cfg.get("subscription-status",
              cfg.get("energize-subscription", {})))
        if isinstance(sub, dict):
            status = sub.get("status", sub.get("enabled", ""))
            if isinstance(status, str) and status.lower() in ("expired", "inactive", "disabled", ""):
                self.findings.append({
                    "id": "FW-003",
                    "title": "Energize Updates subscription expired or inactive",
                    "severity": "HIGH",
                    "category": "Firmware & Updates",
                    "resource": "Subscription",
                    "actual": status or "Inactive",
                    "expected": "Active subscription",
                    "recommendation": "Renew the Energize Updates subscription to receive firmware updates, attack definitions, and virus signatures",
                    "remediation_cmd": "Renew Energize Updates subscription via Barracuda Cloud Control portal"
                })
            expiry = sub.get("expiry-date", sub.get("renewal-date", ""))
            if expiry:
                self.findings.append({
                    "id": "FW-003",
                    "title": f"Energize subscription expiry: {expiry}",
                    "severity": "INFO",
                    "category": "Firmware & Updates",
                    "resource": "Subscription",
                    "actual": f"Expires: {expiry}",
                    "expected": "Active subscription",
                    "recommendation": "Monitor subscription renewal date and plan for timely renewal",
                    "remediation_cmd": "Renew Energize Updates subscription via Barracuda Cloud Control portal"
                })
        elif isinstance(sub, str) and sub.lower() in ("expired", "inactive", "no", ""):
            self.findings.append({
                "id": "FW-003",
                "title": "Energize Updates subscription not active",
                "severity": "HIGH",
                "category": "Firmware & Updates",
                "resource": "Subscription",
                "actual": sub or "Not active",
                "expected": "Active subscription",
                "recommendation": "Activate or renew Energize Updates for continued security definition updates",
                "remediation_cmd": "Renew Energize Updates subscription via Barracuda Cloud Control portal"
            })

    def _check_auto_updates(self, cfg):
        auto_update = cfg.get("auto-update", cfg.get("automatic-updates",
                     cfg.get("firmware-auto-update", {})))
        if isinstance(auto_update, dict):
            enabled = auto_update.get("status", auto_update.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "FW-004",
                    "title": "Automatic definition updates disabled",
                    "severity": "HIGH",
                    "category": "Firmware & Updates",
                    "resource": "Auto-Update",
                    "actual": "Auto-update disabled",
                    "expected": "Automatic updates enabled",
                    "recommendation": "Enable automatic updates for attack definitions and virus signatures to stay protected against new threats",
                    "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/system -H 'Authorization: Basic <token>' -d \"{'auto-update':'enabled'}'''"
                })
        elif isinstance(auto_update, str) and auto_update.lower() in ("off", "no", "disabled", ""):
            self.findings.append({
                "id": "FW-004",
                "title": "Automatic updates disabled",
                "severity": "HIGH",
                "category": "Firmware & Updates",
                "resource": "Auto-Update",
                "actual": "Disabled",
                "expected": "Enabled",
                "recommendation": "Enable automatic security definition updates",
                "remediation_cmd": "curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/system -H 'Authorization: Basic <token>' -d \"{'auto-update':'enabled'}'''"
            })

    def _check_attack_definitions(self, cfg):
        defs = cfg.get("attack-definitions", cfg.get("security-definitions", {}))
        if isinstance(defs, dict):
            version = defs.get("version", defs.get("definition-version", ""))
            last_update = defs.get("last-update", defs.get("updated-on", ""))
            if last_update:
                self.findings.append({
                    "id": "FW-005",
                    "title": f"Attack definitions last updated: {last_update}",
                    "severity": "INFO",
                    "category": "Firmware & Updates",
                    "resource": "Attack Definitions",
                    "actual": f"Version: {version}, Updated: {last_update}",
                    "expected": "Definitions updated within last 7 days",
                    "recommendation": "Verify attack definitions are being updated regularly — outdated definitions leave new threats undetected",
                    "remediation_cmd": "Verify definitions at: ADVANCED > Energize Updates > Attack Definitions"
                })
