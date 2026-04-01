"""Unit tests for Barracuda WAF security scanner using mock API responses."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from checks.waf_policies import WafPoliciesChecker
from checks.ssl_tls import SslTlsChecker
from checks.access_control import AccessControlChecker
from checks.authentication import AuthenticationChecker
from checks.services import ServicesChecker
from checks.network import NetworkChecker
from checks.ddos_protection import DdosProtectionChecker
from checks.bot_protection import BotProtectionChecker
from checks.api_security import ApiSecurityChecker
from checks.logging_monitoring import LoggingMonitoringChecker
from checks.firmware_updates import FirmwareUpdatesChecker
from utils.severity import compute_posture_score, score_to_grade, severity_counts


MOCK_DATA_PATH = os.path.join(os.path.dirname(__file__), "test_data", "mock_responses.json")

with open(MOCK_DATA_PATH, "r", encoding="utf-8") as f:
    MOCK_DATA = json.load(f)


class MockApiClient:
    """Mock API client that returns pre-loaded test data."""

    def __init__(self, data):
        self.data = data

    def get(self, endpoint):
        key = endpoint.strip("/").split("/")[-1]
        return self.data.get(key, {})

    def get_list(self, endpoint, key=None):
        data = self.get(endpoint)
        if not data:
            return []
        if "data" in data:
            inner = data["data"]
            if isinstance(inner, dict):
                if key and key in inner:
                    val = inner[key]
                    return val if isinstance(val, list) else [val]
                for v in inner.values():
                    if isinstance(v, list):
                        return v
            elif isinstance(inner, list):
                return inner
        return [data] if isinstance(data, dict) else []

    def get_system_info(self):
        return self.data.get("system", {})

    def get_services(self):
        return self.get_list("/services", key="services")

    def get_service_detail(self, name):
        for svc in self.get_services():
            if svc.get("name") == name:
                return {"data": svc}
        return {}

    def get_security_policies(self):
        return self.get_list("/security-policies", key="security-policies")

    def get_security_policy(self, name):
        for p in self.get_security_policies():
            if p.get("name") == name:
                return {"data": p}
        return {}

    def get_certificates(self):
        return self.get_list("/signed-certificate", key="signed-certificate")

    def get_trusted_certificates(self):
        return self.get_list("/trusted-certificate", key="trusted-certificate")

    def get_network_interfaces(self):
        return self.data.get("network_interface", {}).get("data", {}).get("interface", [])

    def get_vlans(self):
        return self.data.get("network_vlan", {}).get("data", {}).get("vlan", [])

    def get_access_control(self, service_name):
        return self.data.get("global-acls", {}).get("data", {}).get("global-acls", [])

    def get_rate_control(self, service_name):
        return self.data.get("rate-control", {}).get("data", {}).get("rate-control", [])

    def get_content_rules(self, service_name):
        return []

    def get_logging_config(self):
        return self.data.get("syslog", {})

    def get_admin_config(self):
        return self.data.get("admin", {})

    def get_cluster_config(self):
        return self.data.get("cluster", {})


class TestWafPolicies(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = WafPoliciesChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)

    def test_sql_injection_disabled(self):
        findings = self.checker.run_all()
        sqli = [f for f in findings if f["id"] == "WAF-POL-011"]
        self.assertTrue(len(sqli) > 0, "Should flag disabled SQL injection protection")

    def test_xss_disabled(self):
        findings = self.checker.run_all()
        xss = [f for f in findings if f["id"] == "WAF-POL-012"]
        self.assertTrue(len(xss) > 0, "Should flag disabled XSS protection")

    def test_xxe_disabled(self):
        findings = self.checker.run_all()
        xxe = [f for f in findings if f["id"] == "WAF-POL-025"]
        self.assertTrue(len(xxe) > 0, "Should flag disabled XXE protection")


class TestSslTls(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = SslTlsChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)

    def test_weak_protocols_flagged(self):
        findings = self.checker.run_all()
        weak = [f for f in findings if f["id"] == "SSL-001"]
        self.assertTrue(len(weak) > 0, "Should flag weak TLS protocols")

    def test_weak_ciphers_flagged(self):
        findings = self.checker.run_all()
        ciphers = [f for f in findings if f["id"] == "SSL-003"]
        self.assertTrue(len(ciphers) > 0, "Should flag weak cipher suites")

    def test_weak_key_size(self):
        findings = self.checker.run_all()
        keys = [f for f in findings if f["id"] == "SSL-015"]
        self.assertTrue(len(keys) > 0, "Should flag 1024-bit key size")


class TestAccessControl(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = AccessControlChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)

    def test_allow_all_acl(self):
        findings = self.checker.run_all()
        allow_all = [f for f in findings if f["id"] == "ACL-002"]
        self.assertTrue(len(allow_all) > 0, "Should flag allow-all ACL rules")


class TestAuthentication(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = AuthenticationChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)

    def test_mfa_disabled(self):
        findings = self.checker.run_all()
        mfa = [f for f in findings if f["id"] == "AUTH-005"]
        self.assertTrue(len(mfa) > 0, "Should flag disabled MFA")

    def test_default_admin(self):
        findings = self.checker.run_all()
        admin = [f for f in findings if f["id"] == "AUTH-001"]
        self.assertTrue(len(admin) > 0, "Should flag default admin accounts")


class TestServices(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = ServicesChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)

    def test_no_policy_assigned(self):
        findings = self.checker.run_all()
        no_policy = [f for f in findings if f["id"] == "SVC-006"]
        self.assertTrue(len(no_policy) > 0, "Should flag service without security policy")

    def test_http_service(self):
        findings = self.checker.run_all()
        http = [f for f in findings if f["id"] == "SVC-007"]
        self.assertTrue(len(http) > 0, "Should flag unencrypted HTTP service")


class TestNetwork(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = NetworkChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)

    def test_telnet_enabled(self):
        findings = self.checker.run_all()
        telnet = [f for f in findings if f["id"] == "NET-007"]
        self.assertTrue(len(telnet) > 0, "Should flag enabled Telnet")

    def test_snmp_v2(self):
        findings = self.checker.run_all()
        snmp = [f for f in findings if f["id"] == "NET-008"]
        self.assertTrue(len(snmp) > 0, "Should flag SNMP v2c")


class TestDdos(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = DdosProtectionChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)


class TestBotProtection(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = BotProtectionChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)


class TestApiSecurity(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = ApiSecurityChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)


class TestLogging(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = LoggingMonitoringChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)

    def test_no_syslog(self):
        findings = self.checker.run_all()
        syslog = [f for f in findings if f["id"] == "LOG-001"]
        self.assertTrue(len(syslog) > 0, "Should flag missing syslog server")


class TestFirmware(unittest.TestCase):
    def setUp(self):
        self.client = MockApiClient(MOCK_DATA)
        self.checker = FirmwareUpdatesChecker(self.client)

    def test_findings_generated(self):
        findings = self.checker.run_all()
        self.assertGreater(len(findings), 0)

    def test_eol_firmware(self):
        findings = self.checker.run_all()
        eol = [f for f in findings if f["id"] == "FW-002"]
        self.assertTrue(len(eol) > 0, "Should flag EOL firmware version 11.x")


class TestScoring(unittest.TestCase):
    def test_perfect_score(self):
        self.assertEqual(compute_posture_score([]), 100)

    def test_score_with_critical(self):
        findings = [{"severity": "CRITICAL"}]
        self.assertEqual(compute_posture_score(findings), 85)

    def test_score_clamped_to_zero(self):
        findings = [{"severity": "CRITICAL"}] * 20
        self.assertEqual(compute_posture_score(findings), 0)

    def test_grade_a(self):
        self.assertEqual(score_to_grade(95), "A")

    def test_grade_f(self):
        self.assertEqual(score_to_grade(50), "F")

    def test_severity_counts(self):
        findings = [
            {"severity": "CRITICAL"},
            {"severity": "HIGH"},
            {"severity": "HIGH"},
            {"severity": "MEDIUM"},
        ]
        counts = severity_counts(findings)
        self.assertEqual(counts["CRITICAL"], 1)
        self.assertEqual(counts["HIGH"], 2)
        self.assertEqual(counts["MEDIUM"], 1)
        self.assertEqual(counts["LOW"], 0)


if __name__ == "__main__":
    unittest.main()
