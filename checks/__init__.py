from .waf_policies import WafPoliciesChecker
from .ssl_tls import SslTlsChecker
from .access_control import AccessControlChecker
from .authentication import AuthenticationChecker
from .services import ServicesChecker
from .network import NetworkChecker
from .ddos_protection import DdosProtectionChecker
from .bot_protection import BotProtectionChecker
from .api_security import ApiSecurityChecker
from .logging_monitoring import LoggingMonitoringChecker
from .firmware_updates import FirmwareUpdatesChecker
from .content_rules import ContentRulesChecker
from .adaptive_profiling import AdaptiveProfilingChecker
from .backup_recovery import BackupRecoveryChecker
from .license_capacity import LicenseCapacityChecker
from .cve_checks import CveChecker

ALL_CHECKERS = {
    "waf_policies": WafPoliciesChecker,
    "ssl_tls": SslTlsChecker,
    "access_control": AccessControlChecker,
    "authentication": AuthenticationChecker,
    "services": ServicesChecker,
    "network": NetworkChecker,
    "ddos_protection": DdosProtectionChecker,
    "bot_protection": BotProtectionChecker,
    "api_security": ApiSecurityChecker,
    "logging_monitoring": LoggingMonitoringChecker,
    "firmware_updates": FirmwareUpdatesChecker,
    "content_rules": ContentRulesChecker,
    "adaptive_profiling": AdaptiveProfilingChecker,
    "backup_recovery": BackupRecoveryChecker,
    "license_capacity": LicenseCapacityChecker,
    "cve_checks": CveChecker,
}
