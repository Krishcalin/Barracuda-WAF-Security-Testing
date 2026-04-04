"""Bot protection security checks."""

import logging
from utils.config_helper import safe_int, deep_get, extract_config

logger = logging.getLogger(__name__)


class BotProtectionChecker:
    """Assess bot protection — bot detection, CAPTCHA, client fingerprinting,
    JavaScript challenge."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running bot protection checks...")
        services = self.api.get_services()

        for svc in services:
            name = svc.get("name", svc.get("id", "unknown"))
            detail = self.api.get_service_detail(name)
            cfg = extract_config(detail, fallback=svc) if isinstance(detail, dict) else svc

            self._check_bot_mitigation(name, cfg)
            self._check_captcha(name, cfg)
            self._check_client_fingerprinting(name, cfg)
            self._check_js_challenge(name, cfg)
            self._check_known_bot_signatures(name, cfg)
            self._check_crawler_protection(name, cfg)

        return self.findings

    def _check_bot_mitigation(self, name, cfg):
        bot = cfg.get("bot-mitigation", cfg.get("advanced-bot-protection", cfg.get("bot-protection", {})))
        if isinstance(bot, dict):
            enabled = bot.get("status", bot.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "BOT-001",
                    "title": "Bot mitigation disabled",
                    "severity": "HIGH",
                    "category": "Bot Protection",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Bot mitigation enabled",
                    "recommendation": "Enable bot mitigation to detect and block automated attacks, scrapers, and credential stuffing bots",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/bot-mitigation -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })
        elif not bot:
            self.findings.append({
                "id": "BOT-001",
                "title": "Bot mitigation not configured",
                "severity": "HIGH",
                "category": "Bot Protection",
                "resource": name,
                "actual": "Not configured",
                "expected": "Bot protection enabled",
                "recommendation": "Configure bot mitigation with appropriate detection methods and response actions",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/bot-mitigation -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
            })

    def _check_captcha(self, name, cfg):
        captcha = cfg.get("captcha", cfg.get("bot-mitigation", {}).get("captcha", {}))
        if isinstance(captcha, dict):
            enabled = captcha.get("status", captcha.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "BOT-002",
                    "title": "CAPTCHA challenge disabled",
                    "severity": "MEDIUM",
                    "category": "Bot Protection",
                    "resource": name,
                    "actual": "CAPTCHA disabled",
                    "expected": "CAPTCHA enabled for suspicious clients",
                    "recommendation": "Enable CAPTCHA challenges for clients that exhibit bot-like behavior",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/bot-mitigation/captcha -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })
        elif not captcha:
            self.findings.append({
                "id": "BOT-002",
                "title": "CAPTCHA challenge not configured",
                "severity": "MEDIUM",
                "category": "Bot Protection",
                "resource": name,
                "actual": "Not configured",
                "expected": "CAPTCHA challenge available",
                "recommendation": "Configure CAPTCHA as a response action for suspected bot traffic",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/bot-mitigation/captcha -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
            })

    def _check_client_fingerprinting(self, name, cfg):
        fp = cfg.get("client-fingerprinting", cfg.get("device-fingerprint", cfg.get("bot-mitigation", {}).get("fingerprinting", {})))
        if isinstance(fp, dict):
            enabled = fp.get("status", fp.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "BOT-003",
                    "title": "Client fingerprinting disabled",
                    "severity": "MEDIUM",
                    "category": "Bot Protection",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Fingerprinting enabled",
                    "recommendation": "Enable client fingerprinting to identify and track bot behavior across IP changes",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/bot-mitigation/fingerprinting -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })
        elif not fp:
            self.findings.append({
                "id": "BOT-003",
                "title": "Client fingerprinting not configured",
                "severity": "MEDIUM",
                "category": "Bot Protection",
                "resource": name,
                "actual": "Not configured",
                "expected": "Client fingerprinting enabled",
                "recommendation": "Configure client fingerprinting for advanced bot detection capabilities",
                "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/bot-mitigation/fingerprinting -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
            })

    def _check_js_challenge(self, name, cfg):
        js = cfg.get("javascript-challenge", cfg.get("bot-mitigation", {}).get("javascript-validation", {}))
        if isinstance(js, dict):
            enabled = js.get("status", js.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "BOT-004",
                    "title": "JavaScript challenge disabled",
                    "severity": "MEDIUM",
                    "category": "Bot Protection",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "JS challenge enabled for suspected bots",
                    "recommendation": "Enable JavaScript challenge to verify clients can execute JS — blocks headless bots and simple scrapers",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/bot-mitigation/javascript-validation -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })

    def _check_known_bot_signatures(self, name, cfg):
        sigs = cfg.get("bot-signatures", cfg.get("bot-mitigation", {}).get("known-bots", {}))
        if isinstance(sigs, dict):
            block_bad = sigs.get("block-known-bad-bots", sigs.get("malicious-bots", ""))
            if isinstance(block_bad, str) and block_bad.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "BOT-005",
                    "title": "Known malicious bot signature blocking disabled",
                    "severity": "HIGH",
                    "category": "Bot Protection",
                    "resource": name,
                    "actual": "Malicious bot blocking disabled",
                    "expected": "Known malicious bots blocked",
                    "recommendation": "Enable blocking of known malicious bot signatures to prevent automated attacks",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/bot-mitigation/known-bots -H 'Authorization: Basic <token>' -d \"{'block-known-bad-bots':'on'}'''")
                })
            update = sigs.get("auto-update", sigs.get("signature-update", ""))
            if isinstance(update, str) and update.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "BOT-006",
                    "title": "Bot signature auto-update disabled",
                    "severity": "MEDIUM",
                    "category": "Bot Protection",
                    "resource": name,
                    "actual": "Auto-update disabled",
                    "expected": "Auto-update enabled",
                    "recommendation": "Enable automatic bot signature updates to stay current with emerging bot threats",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/bot-mitigation/known-bots -H 'Authorization: Basic <token>' -d \"{'auto-update':'on'}'''")
                })

    def _check_crawler_protection(self, name, cfg):
        crawler = cfg.get("web-scraping-protection", cfg.get("anti-scraping", {}))
        if isinstance(crawler, dict):
            enabled = crawler.get("status", crawler.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "BOT-007",
                    "title": "Web scraping protection disabled",
                    "severity": "LOW",
                    "category": "Bot Protection",
                    "resource": name,
                    "actual": "Disabled",
                    "expected": "Anti-scraping protection enabled",
                    "recommendation": "Enable web scraping protection to prevent unauthorized content harvesting",
                    "remediation_cmd": ("curl -X PUT https://<WAF_IP>:8443/restapi/v3.2/services/" + name + "/web-scraping-protection -H 'Authorization: Basic <token>' -d \"{'status':'enabled'}'''")
                })
        honeytraps = cfg.get("honeytraps", cfg.get("honeypot", ""))
        if not honeytraps or (isinstance(honeytraps, str) and honeytraps.lower() in ("off", "disabled", "")):
            self.findings.append({
                "id": "BOT-008",
                "title": "Honeytrap (honeypot) links not configured",
                "severity": "INFO",
                "category": "Bot Protection",
                "resource": name,
                "actual": "No honeytraps",
                "expected": "Honeytraps for crawler detection",
                "recommendation": "Consider adding hidden honeytrap links to detect bots that follow invisible links",
                "remediation_cmd": "Configure honeytrap links via WAF management console: WEBSITES > Bot Mitigation"
            })
