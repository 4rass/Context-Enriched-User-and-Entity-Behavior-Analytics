"""Idempotent synthetic demo data for CE-UEBA.

All names, e-mail addresses, IPs and organizations are fictional.
IPs use documentation-safe ranges (RFC 5737): 192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24.

Timestamps are generated relative to the moment of seeding so the demo
scenarios (30-day promotion window, active change windows, etc.) always
behave correctly in a live presentation.
"""

from datetime import datetime, timedelta

import risk_engine
from models import Alert, BehavioralLog, ChangeTicket, ITAsset, Role, User, db

NOW = datetime.utcnow()
H = timedelta(hours=1)
D = timedelta(days=1)

ROLES = [
    ("Customer Service Agent", 1),
    ("Financial Analyst", 3),
    ("Senior Financial Analyst", 4),
    ("DevOps Engineer", 4),
    ("IT Administrator", 4),
    ("Database Administrator", 5),
]

ASSETS = [
    # hostname, ip, criticality, asset_type, owner_department
    ("finapp-prod-01", "192.0.2.11", "Critical", "Application Server", "IT Operations"),
    ("finreport-prod-01", "192.0.2.12", "Critical", "Reporting Server", "Finance"),
    ("db-core-fin-01", "192.0.2.13", "Critical", "Database Server", "Finance"),
    ("idp-server-01", "192.0.2.14", "Critical", "Identity Server", "IT Security"),
    ("devops-jump-01", "192.0.2.15", "Medium", "Jump Host", "IT Operations"),
    ("hr-intranet-01", "192.0.2.16", "Low", "Web Server", "Human Resources"),
    ("backup-nas-01", "192.0.2.17", "Medium", "Storage", "IT Operations"),
    ("cs-wks-42", "198.51.100.42", "Low", "Workstation", "Customer Service"),
    ("monitoring-node-01", "198.51.100.21", "Medium", "Monitoring", "IT Operations"),
    ("trading-edge-01", "203.0.113.30", "High", "Trading Server", "Treasury"),
]

USERS = [
    # username, full_name, email, department, status, role, prev_role, role_change_date
    ("aylin.kaya", "Aylin Kaya", "aylin.kaya@finanstech.example",
     "IT Operations", "Active", "DevOps Engineer", None, None),
    ("selin.yilmaz", "Selin Yilmaz", "selin.yilmaz@finanstech.example",
     "Finance", "Active", "Senior Financial Analyst", "Financial Analyst", NOW - 10 * D),
    ("can.korkmaz", "Can Korkmaz", "can.korkmaz@finanstech.example",
     "IT Operations", "Suspended", "Database Administrator", None, None),
    ("mert.simsek", "Mert Simsek", "mert.simsek@finanstech.example",
     "Finance", "Active", "Financial Analyst", None, None),
    ("zeynep.arslan", "Zeynep Arslan", "zeynep.arslan@finanstech.example",
     "IT Operations", "Active", "IT Administrator", None, None),
    ("burak.ozturk", "Burak Ozturk", "burak.ozturk@finanstech.example",
     "Customer Service", "Active", "Customer Service Agent", None, None),
    ("elif.sahin", "Elif Sahin", "elif.sahin@finanstech.example",
     "Finance", "Active", "Financial Analyst", None, None),
    ("dogan.aydin", "Dogan Aydin", "dogan.aydin@finanstech.example",
     "IT Operations", "Active", "Database Administrator", None, None),
    ("kerem.tan", "Kerem Tan", "kerem.tan@finanstech.example",
     "IT Operations", "Active", "DevOps Engineer", None, None),
    ("nihan.dogan", "Nihan Dogan", "nihan.dogan@finanstech.example",
     "Customer Service", "Active", "Customer Service Agent", None, None),
    ("osman.kilic", "Osman Kilic", "osman.kilic@finanstech.example",
     "Treasury", "Active", "Senior Financial Analyst", None, None),
    ("ecem.gunes", "Ecem Gunes", "ecem.gunes@finanstech.example",
     "Human Resources", "Active", "Customer Service Agent", None, None),
]

TICKETS = [
    # user, asset, change_type, start, end, status, description
    ("aylin.kaya", "finapp-prod-01", "Software Deployment",
     NOW - 3 * H, NOW + 5 * H, "In Progress",
     "Nightly release of banking application v4.12.2 to production."),
    ("zeynep.arslan", "monitoring-node-01", "Scheduled Maintenance",
     NOW - 2 * H, NOW + 4 * H, "Approved",
     "Firmware upgrade and monitoring agent reconfiguration."),
    ("selin.yilmaz", "finreport-prod-01", "Access Request",
     NOW - 5 * D, NOW - 4 * D, "Completed",
     "Temporary elevated read access for quarter-close activities."),
    ("dogan.aydin", "db-core-fin-01", "Database Patching",
     NOW + 2 * D, NOW + 3 * D, "Approved",
     "Quarterly security patch rollout for the core finance database."),
    ("kerem.tan", "devops-jump-01", "Configuration Update",
     NOW - 5 * D, NOW - 4 * D, "Completed",
     "Baseline hardening update for the DevOps jump host."),
    ("burak.ozturk", "cs-wks-42", "Software Install",
     NOW - 10 * D, NOW - 9 * D, "Completed",
     "CRM client installation on customer service workstation."),
    ("can.korkmaz", "idp-server-01", "Account Disable Procedure",
     NOW - 2 * D, NOW - 1 * D, "Completed",
     "Identity cleanup following account suspension."),
    ("aylin.kaya", "devops-jump-01", "Routine Deployment",
     NOW - 1 * D, NOW - 1 * D + 8 * H, "Completed",
     "Routine CI pipeline deployment through the jump host."),
    ("zeynep.arslan", "backup-nas-01", "Backup Retention Change",
     NOW - 6 * D, NOW - 5 * D, "Completed",
     "Adjustment of nightly backup retention window."),
    ("osman.kilic", "trading-edge-01", "Trading Threshold Adjustment",
     NOW - 1 * H, NOW + 3 * H, "Approved",
     "Adjust intraday trading limits under change control."),
    ("elif.sahin", "db-core-fin-01", "Quarterly Report Extract",
     NOW - 3 * D, NOW - 2 * D, "Completed",
     "Approved analytical extract for quarterly reporting."),
    ("mert.simsek", "finreport-prod-01", "Reporting Access Review",
     NOW + 5 * D, NOW + 6 * D, "Approved",
     "Scheduled access review for reporting self-service."),
]

# Anomalous logs -> one alert each (20 alerts).
ANOMALOUS_LOGS = [
    # user, asset, event, hours_ago, raw_score, details, source_ip, anomaly, analyst_status
    # Scenario A - approved software deployment (suppressed)
    ("aylin.kaya", "finapp-prod-01", "software_deployment", 1, 82,
     "Deployment of build 4.12.2 executed at an unusual hour",
     "192.0.2.15", "Unusual deployment time", "Investigating"),
    # Scenario B - recent promotion, first access to new system (suppressed)
    ("selin.yilmaz", "finreport-prod-01", "remote_login", 3, 50,
     "First login to the newly assigned financial reporting system, after hours",
     "203.0.113.77", "First-seen asset access", "Open"),
    # Scenario C - suspended employee bulk export from critical DB (active, Critical)
    ("can.korkmaz", "db-core-fin-01", "bulk_export", 2, 70,
     "Export of 148,000 customer records from the core finance database",
     "192.0.2.99", "Large data export", "Confirmed Threat"),
    # Scenario D - unauthorized privilege escalation on identity server (active, Critical)
    ("mert.simsek", "idp-server-01", "privilege_escalation", 5, 65,
     "Attempt to add a personal account to the Domain Admins group",
     "198.51.100.55", "Privilege escalation attempt", "Confirmed Threat"),
    # Scenario E - legitimate maintenance covered by ITSM ticket (suppressed)
    ("zeynep.arslan", "monitoring-node-01", "configuration_change", 1, 72,
     "Monitoring agent thresholds reconfigured on the monitoring node",
     "198.51.100.21", "Configuration change velocity", "Closed as Benign"),
    # Supporting scene - cross-department access without ticket (active)
    ("burak.ozturk", "hr-intranet-01", "remote_login", 8, 45,
     "Off-hours login to the HR portal from outside the HR department",
     "198.51.100.42", "Cross-department access", "Investigating"),
    # Supporting scene - event outside the (expired) approved window (active)
    ("elif.sahin", "db-core-fin-01", "data_export", 26, 40,
     "Analytical extract executed after the approved window had closed",
     "192.0.2.12", "Data volume spike", "Open"),
    ("dogan.aydin", "db-core-fin-01", "configuration_change", 30, 60,
     "Database parameter modified on the core finance database",
     "192.0.2.18", "Configuration drift", "Open"),
    # Departmental alignment alone is never enough to suppress:
    ("kerem.tan", "devops-jump-01", "remote_login", 2, 30,
     "Off-hours login to the DevOps jump host",
     "192.0.2.150", "Off-hours access", "Open"),
    ("nihan.dogan", "cs-wks-42", "password_reset", 20, 35,
     "Three password resets within a single hour",
     "198.51.100.42", "Password reset burst", "Closed as Benign"),
    ("osman.kilic", "trading-edge-01", "configuration_change", 0.5, 55,
     "Trading limit thresholds adjusted on the trading edge server",
     "203.0.113.30", "Configuration change", "Closed as Benign"),
    ("ecem.gunes", "hr-intranet-01", "remote_login", 6, 42,
     "Weekend access to the HR intranet portal",
     "192.0.2.160", "Weekend access", "Open"),
    ("aylin.kaya", "db-core-fin-01", "file_access", 12, 48,
     "Access to finance ledger files by a DevOps engineer",
     "192.0.2.15", "Cross-department data access", "Investigating"),
    ("dogan.aydin", "backup-nas-01", "unauthorized_configuration_change", 4, 58,
     "Backup schedule modified without a matching change ticket",
     "192.0.2.18", "Configuration drift", "Open"),
    ("mert.simsek", "finreport-prod-01", "remote_login", 48, 38,
     "Login to the reporting server from a workstation subnet",
     "198.51.100.55", "First-seen asset access", "Closed as Benign"),
    ("selin.yilmaz", "db-core-fin-01", "data_export", 30, 60,
     "Bulk extract of financial records from the core database",
     "203.0.113.77", "Data volume spike", "Open"),
    ("burak.ozturk", "db-core-fin-01", "remote_login", 10, 40,
     "Customer service agent accessed the core finance database",
     "198.51.100.42", "Cross-department access", "Open"),
    ("zeynep.arslan", "idp-server-01", "disabled_security_control", 72, 55,
     "MFA requirement temporarily disabled on the identity server",
     "192.0.2.14", "Security control manipulation", "Open"),
    ("kerem.tan", "finapp-prod-01", "configuration_change", 26, 50,
     "Application server configuration edited outside deployment window",
     "192.0.2.150", "Configuration drift", "Open"),
    ("elif.sahin", "finapp-prod-01", "bulk_export", 8, 45,
     "Transaction batch exported from the production banking application",
     "192.0.2.12", "Large data export", "Investigating"),
]

# Routine activity with no anomaly -> behavioral logs without alerts.
ROUTINE_LOGS = [
    # user, asset, event, hours_ago, details, source_ip
    ("aylin.kaya", "devops-jump-01", "remote_login", 6,
     "Routine jump host login", "192.0.2.15"),
    ("zeynep.arslan", "monitoring-node-01", "remote_login", 12,
     "Routine monitoring node login", "198.51.100.21"),
    ("dogan.aydin", "db-core-fin-01", "database_query", 4,
     "Scheduled maintenance query", "192.0.2.18"),
    ("elif.sahin", "finreport-prod-01", "file_access", 7,
     "Report template access", "192.0.2.12"),
    ("burak.ozturk", "cs-wks-42", "remote_login", 24,
     "Daily workstation login", "198.51.100.42"),
    ("nihan.dogan", "cs-wks-42", "vpn_connection", 30,
     "Standard VPN session", "198.51.100.51"),
    ("osman.kilic", "trading-edge-01", "remote_login", 10,
     "Trading console login", "203.0.113.31"),
    ("ecem.gunes", "hr-intranet-01", "remote_login", 26,
     "HR portal login", "192.0.2.160"),
    ("mert.simsek", "finreport-prod-01", "file_access", 50,
     "Monthly report access", "198.51.100.55"),
    ("kerem.tan", "devops-jump-01", "software_deployment", 60,
     "Routine CI build deployment", "192.0.2.150"),
]


def seed_database(verbose=True):
    """Populate the database with demo data. Safe to run repeatedly."""
    if db.session.query(User.user_id).limit(1).first() is not None:
        if verbose:
            print("Database already contains data; seeding skipped (idempotent).")
        return False

    roles = {}
    for name, level in ROLES:
        role = Role(role_name=name, clearance_level=level)
        db.session.add(role)
        roles[name] = role

    assets = {}
    for hostname, ip, crit, atype, dept in ASSETS:
        asset = ITAsset(hostname=hostname, ip_address=ip,
                       criticality_level=crit, asset_type=atype,
                       owner_department=dept)
        db.session.add(asset)
        assets[hostname] = asset

    users = {}
    for (username, full_name, email, dept, status,
         role_name, prev_role_name, change_date) in USERS:
        user = User(
            username=username, full_name=full_name, email=email,
            department=dept, employment_status=status,
            role=roles[role_name],
            previous_role=roles.get(prev_role_name) if prev_role_name else None,
            role_change_date=change_date,
        )
        db.session.add(user)
        users[username] = user

    db.session.flush()  # assign primary keys and satisfy pending FK resolution

    for username, hostname, ctype, start, end, status, desc in TICKETS:
        db.session.add(ChangeTicket(
            user=users[username], asset=assets[hostname], change_type=ctype,
            approved_start=start, approved_end=end, status=status,
            description=desc,
        ))

    for (username, hostname, event_type, hours_ago, raw, details,
         source_ip, anomaly, analyst_status) in ANOMALOUS_LOGS:
        user = users[username]
        asset = assets[hostname]
        log = BehavioralLog(
            user=user, asset=asset, event_type=event_type,
            timestamp=NOW - timedelta(hours=hours_ago),
            details=details, source_ip=source_ip, anomaly_type=anomaly,
        )
        db.session.add(log)

        # Autoflush makes the pending tickets visible to this query.
        user_tickets = ChangeTicket.query.filter_by(user_id=user.user_id).all()
        result = risk_engine.evaluate_alert(
            log=log, user=user, role=user.role,
            previous_role=user.previous_role, asset=asset,
            change_tickets=user_tickets, raw_ml_score=raw,
            evaluation_time=NOW,
        )
        db.session.add(Alert(
            log=log, user=user,
            raw_ml_risk_score=result["raw_score"],
            context_adjusted_risk_score=result["adjusted_score"],
            suppression_status=result["suppression_status"],
            suppression_reason=result["suppression_reason"],
            severity=result["severity"],
            created_at=log.timestamp + timedelta(minutes=10),
            analyst_status=analyst_status,
            context_factors=risk_engine.factors_to_json(result["factors"]),
        ))

    for username, hostname, event_type, hours_ago, details, source_ip in ROUTINE_LOGS:
        db.session.add(BehavioralLog(
            user=users[username], asset=assets[hostname], event_type=event_type,
            timestamp=NOW - timedelta(hours=hours_ago),
            details=details, source_ip=source_ip, anomaly_type=None,
        ))

    db.session.commit()
    if verbose:
        print("Seeded CE-UEBA demo data: "
              f"{len(ROLES)} roles, {len(USERS)} users, {len(ASSETS)} assets, "
              f"{len(TICKETS)} change tickets, "
              f"{len(ANOMALOUS_LOGS) + len(ROUTINE_LOGS)} behavioral logs, "
              f"{len(ANOMALOUS_LOGS)} alerts.")
    return True


if __name__ == "__main__":
    from app import create_app
    app = create_app()
    with app.app_context():
        db.create_all()
        seed_database()
