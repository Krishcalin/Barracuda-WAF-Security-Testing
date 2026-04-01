"""Backup and disaster recovery configuration checks."""

import logging

logger = logging.getLogger(__name__)


class BackupRecoveryChecker:
    """Assess backup and DR — configuration backups, scheduled exports,
    backup encryption, cloud backup, and recovery testing."""

    def __init__(self, api_client):
        self.api = api_client
        self.findings = []

    def run_all(self):
        logger.info("Running backup and recovery checks...")
        sys_info = self.api.get_system_info()
        cfg = sys_info.get("data", sys_info) if isinstance(sys_info, dict) else {}
        admin_cfg = self.api.get_admin_config()
        admin = admin_cfg.get("data", admin_cfg) if isinstance(admin_cfg, dict) else {}
        backup_cfg = self.api.get_backup_config()
        backup_data = backup_cfg.get("data", backup_cfg) if isinstance(backup_cfg, dict) else {}
        # Merge backup data into cfg for lookup
        if backup_data and "backup" not in cfg:
            cfg["backup"] = backup_data
        cluster = self.api.get_cluster_config()
        cluster_cfg = cluster.get("data", cluster) if isinstance(cluster, dict) else {}

        self._check_scheduled_backup(cfg, admin)
        self._check_backup_encryption(cfg, admin)
        self._check_cloud_backup(cfg, admin)
        self._check_backup_destination(cfg, admin)
        self._check_config_export(cfg, admin)
        self._check_backup_retention(cfg, admin)
        self._check_ha_config_sync(cluster_cfg)
        self._check_recovery_point(cfg, admin)

        return self.findings

    def _check_scheduled_backup(self, cfg, admin):
        backup = cfg.get("backup", admin.get("backup", admin.get("scheduled-backup", {})))
        if isinstance(backup, dict):
            enabled = backup.get("status", backup.get("enabled", backup.get("scheduled", "")))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "BKP-001",
                    "title": "Scheduled configuration backup disabled",
                    "severity": "HIGH",
                    "category": "Backup & Recovery",
                    "resource": "Backup Schedule",
                    "actual": "Scheduled backup disabled",
                    "expected": "Daily or weekly scheduled backups",
                    "recommendation": "Enable scheduled configuration backups to ensure recovery capability after misconfiguration, hardware failure, or security incidents"
                })
            else:
                freq = backup.get("frequency", backup.get("schedule", backup.get("interval", "")))
                if isinstance(freq, str) and freq.lower() in ("monthly", "quarterly", "yearly"):
                    self.findings.append({
                        "id": "BKP-002",
                        "title": f"Backup frequency too low: {freq}",
                        "severity": "MEDIUM",
                        "category": "Backup & Recovery",
                        "resource": "Backup Schedule",
                        "actual": f"Backup frequency: {freq}",
                        "expected": "Daily or weekly backups",
                        "recommendation": "Increase backup frequency to daily or weekly to minimize configuration loss window"
                    })
        elif not backup:
            self.findings.append({
                "id": "BKP-001",
                "title": "No backup configuration found",
                "severity": "HIGH",
                "category": "Backup & Recovery",
                "resource": "Backup Schedule",
                "actual": "No backup configuration",
                "expected": "Scheduled configuration backups",
                "recommendation": "Configure scheduled backups — without backups, a WAF failure or misconfiguration could require complete reconfiguration"
            })

    def _check_backup_encryption(self, cfg, admin):
        backup = cfg.get("backup", admin.get("backup", {}))
        if isinstance(backup, dict):
            encryption = backup.get("encryption", backup.get("encrypt-backup", ""))
            if isinstance(encryption, str) and encryption.lower() in ("off", "no", "disabled", "none", ""):
                self.findings.append({
                    "id": "BKP-003",
                    "title": "Configuration backup encryption disabled",
                    "severity": "HIGH",
                    "category": "Backup & Recovery",
                    "resource": "Backup Encryption",
                    "actual": "Backups not encrypted",
                    "expected": "AES-256 encrypted backups",
                    "recommendation": "Enable backup encryption — unencrypted backups expose WAF credentials, SSL private keys, and security policy details"
                })

    def _check_cloud_backup(self, cfg, admin):
        cloud = cfg.get("cloud-backup", admin.get("cloud-backup", admin.get("barracuda-cloud", {})))
        if isinstance(cloud, dict):
            enabled = cloud.get("status", cloud.get("enabled", ""))
            if isinstance(enabled, str) and enabled.lower() in ("off", "no", "disabled", ""):
                self.findings.append({
                    "id": "BKP-004",
                    "title": "Cloud backup not enabled",
                    "severity": "MEDIUM",
                    "category": "Backup & Recovery",
                    "resource": "Cloud Backup",
                    "actual": "Cloud backup disabled",
                    "expected": "Offsite backup for disaster recovery",
                    "recommendation": "Enable Barracuda Cloud backup or configure remote backup destination for offsite disaster recovery"
                })
        elif not cloud:
            self.findings.append({
                "id": "BKP-004",
                "title": "No offsite/cloud backup configured",
                "severity": "MEDIUM",
                "category": "Backup & Recovery",
                "resource": "Cloud Backup",
                "actual": "No offsite backup",
                "expected": "Offsite backup destination configured",
                "recommendation": "Configure offsite backup (cloud or remote server) to protect against local hardware failure or site disaster"
            })

    def _check_backup_destination(self, cfg, admin):
        backup = cfg.get("backup", admin.get("backup", {}))
        if isinstance(backup, dict):
            dest = backup.get("destination", backup.get("backup-server", backup.get("ftp-server", "")))
            protocol = backup.get("protocol", backup.get("transfer-method", ""))
            if isinstance(protocol, str) and protocol.lower() in ("ftp", "tftp"):
                self.findings.append({
                    "id": "BKP-005",
                    "title": f"Backup transfer uses insecure protocol: {protocol.upper()}",
                    "severity": "HIGH",
                    "category": "Backup & Recovery",
                    "resource": "Backup Transfer",
                    "actual": f"{protocol.upper()} — unencrypted transfer",
                    "expected": "SCP, SFTP, or HTTPS for encrypted backup transfer",
                    "recommendation": "Change backup transfer protocol to SCP, SFTP, or HTTPS — FTP/TFTP transmit backup data (including secrets) in plaintext"
                })

    def _check_config_export(self, cfg, admin):
        export = cfg.get("config-export", admin.get("configuration-export", {}))
        if isinstance(export, dict):
            last_export = export.get("last-export", export.get("last-backup-date", ""))
            if not last_export:
                self.findings.append({
                    "id": "BKP-006",
                    "title": "No recent configuration export recorded",
                    "severity": "MEDIUM",
                    "category": "Backup & Recovery",
                    "resource": "Config Export",
                    "actual": "No export date recorded",
                    "expected": "Regular configuration exports",
                    "recommendation": "Perform regular manual or scheduled configuration exports and store securely for disaster recovery"
                })

    def _check_backup_retention(self, cfg, admin):
        backup = cfg.get("backup", admin.get("backup", {}))
        if isinstance(backup, dict):
            retention = backup.get("retention", backup.get("keep-backups", backup.get("max-backups", 0)))
            try:
                retention = int(retention)
            except (ValueError, TypeError):
                retention = 0
            if retention > 0 and retention < 3:
                self.findings.append({
                    "id": "BKP-007",
                    "title": f"Backup retention too low: {retention} copies",
                    "severity": "MEDIUM",
                    "category": "Backup & Recovery",
                    "resource": "Backup Retention",
                    "actual": f"{retention} backup(s) retained",
                    "expected": ">= 3 backups retained",
                    "recommendation": "Retain at least 3 backup copies to allow rollback to a known-good configuration"
                })

    def _check_ha_config_sync(self, cluster_cfg):
        if isinstance(cluster_cfg, dict):
            status = cluster_cfg.get("status", cluster_cfg.get("ha-mode", ""))
            if isinstance(status, str) and status.lower() not in ("standalone", "disabled", "off", ""):
                sync = cluster_cfg.get("config-sync", cluster_cfg.get("configuration-sync", ""))
                if isinstance(sync, str) and sync.lower() in ("off", "disabled", "no", ""):
                    self.findings.append({
                        "id": "BKP-008",
                        "title": "HA cluster configuration sync disabled",
                        "severity": "HIGH",
                        "category": "Backup & Recovery",
                        "resource": "HA Config Sync",
                        "actual": "Config sync disabled between HA nodes",
                        "expected": "Automatic config sync enabled",
                        "recommendation": "Enable configuration synchronization between HA cluster nodes to ensure consistent security policies after failover"
                    })

    def _check_recovery_point(self, cfg, admin):
        backup = cfg.get("backup", admin.get("backup", {}))
        if isinstance(backup, dict):
            last_backup = backup.get("last-backup", backup.get("last-backup-date", backup.get("last-successful", "")))
            if not last_backup:
                self.findings.append({
                    "id": "BKP-009",
                    "title": "No successful backup recorded",
                    "severity": "HIGH",
                    "category": "Backup & Recovery",
                    "resource": "Recovery Point",
                    "actual": "No successful backup on record",
                    "expected": "Recent successful backup within 7 days",
                    "recommendation": "Verify backup jobs are completing successfully — an unverified backup provides false confidence in recovery capability"
                })
