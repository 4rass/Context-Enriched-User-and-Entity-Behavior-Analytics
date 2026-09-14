"""CE-UEBA context-aware, explainable risk engine (academic simulation).

This module is deliberately framework-independent: it reads plain object
attributes so it can be unit-tested in isolation. It is an explainable
rule-based simulation of contextual risk adjustment - NOT a validated
production detection model.
"""

import json
from datetime import datetime, timedelta

# --- Tunable POC constants -------------------------------------------------
CHANGE_TICKET_REDUCTION = 35.0
ROLE_CHANGE_REDUCTION = 20.0
DEPARTMENT_ALIGNMENT_REDUCTION = 10.0
INACTIVE_EMPLOYEE_INCREASE = 30.0
CRITICAL_ASSET_INCREASE = 15.0
PRIVILEGED_ACTION_INCREASE = 20.0

ROLE_CHANGE_WINDOW_DAYS = 30
SUPPRESSION_SCORE_THRESHOLD = 40.0

APPROVED_TICKET_STATUSES = {"Approved", "In Progress"}
INACTIVE_EMPLOYMENT_STATUSES = {"Terminated", "Suspended"}
CRITICAL_ASSET_LABEL = "Critical"

# Factor categories used for suppression logic and UI color coding.
LEGITIMATE_STRONG = "legitimate_strong"      # can justify suppression
LEGITIMATE_WEAK = "legitimate_weak"          # reduces score, never suppresses alone
SUSPICIOUS = "suspicious"                    # raises score
CRITICAL_SUSPICIOUS = "critical_suspicious"  # raises score and blocks suppression

PRIVILEGED_EVENT_FACTORS = {
    "privilege_escalation": "Privileged action: privilege escalation",
    "bulk_export": "Privileged action: bulk data export",
    "unauthorized_configuration_change": "Privileged action: unauthorized configuration change",
    "disabled_security_control": "Privileged action: security control disabled",
}

_SEVERITY_BANDS = (
    (80.0, "Critical"),
    (60.0, "High"),
    (30.0, "Medium"),
    (0.0, "Low"),
)


def severity_for_score(score):
    """Map a 0-100 risk score to Low / Medium / High / Critical."""
    for threshold, name in _SEVERITY_BANDS:
        if score >= threshold:
            return name
    return "Low"


def find_matching_ticket(log, user, asset, change_tickets):
    """Return the change ticket that legitimately covers this event, if any.

    A ticket matches when: same user, same asset, status is Approved or
    In Progress, and the event timestamp falls inside the approved window.
    """
    if asset is None:
        return None
    for ticket in change_tickets or []:
        if (
            ticket.user_id == user.user_id
            and ticket.asset_id == asset.asset_id
            and ticket.status in APPROVED_TICKET_STATUSES
            and ticket.approved_start <= log.timestamp <= ticket.approved_end
        ):
            return ticket
    return None


def evaluate_alert(log, user, role, previous_role, asset, change_tickets,
                   raw_ml_score, evaluation_time=None):
    """Evaluate one behavioral anomaly with operational context.

    Returns a dict with the adjusted score, suppression decision, severity,
    human-readable explanation and the full list of contextual factors.
    """
    now = evaluation_time or datetime.utcnow()

    # Normalize and clamp the incoming raw score to 0-100 first.
    raw = round(min(100.0, max(0.0, float(raw_ml_score))), 1)
    score = raw
    factors = []

    # --- Rule 1: approved ITSM change window ------------------------------
    ticket = find_matching_ticket(log, user, asset, change_tickets)
    if ticket is not None:
        score -= CHANGE_TICKET_REDUCTION
        factors.append({
            "factor": "Approved ITSM change window",
            "impact": -CHANGE_TICKET_REDUCTION,
            "category": LEGITIMATE_STRONG,
            "detail": (
                f"Event matched approved change ticket #{ticket.ticket_id} "
                f"({ticket.change_type}, status {ticket.status}) on the same "
                f"asset inside its authorized window"
            ),
        })

    # --- Rule 2: recent authorized promotion / role change ----------------
    if (
        user.role_change_date is not None
        and role is not None
        and previous_role is not None
        and timedelta(0) <= now - user.role_change_date <= timedelta(days=ROLE_CHANGE_WINDOW_DAYS)
        and role.clearance_level >= previous_role.clearance_level
    ):
        score -= ROLE_CHANGE_REDUCTION
        factors.append({
            "factor": "Recent authorized role change",
            "impact": -ROLE_CHANGE_REDUCTION,
            "category": LEGITIMATE_STRONG,
            "detail": (
                f"User was promoted to {role.role_name} "
                f"(clearance {role.clearance_level}, >= previous clearance "
                f"{previous_role.clearance_level}) within the last "
                f"{ROLE_CHANGE_WINDOW_DAYS} days"
            ),
        })

    # --- Rule 3: departmental asset alignment -----------------------------
    if (
        asset is not None
        and user.department
        and asset.owner_department == user.department
    ):
        score -= DEPARTMENT_ALIGNMENT_REDUCTION
        factors.append({
            "factor": "Departmental asset alignment",
            "impact": -DEPARTMENT_ALIGNMENT_REDUCTION,
            "category": LEGITIMATE_WEAK,
            "detail": (
                f"Asset is owned by the user's own department "
                f"({user.department})"
            ),
        })

    # --- Rule 4: terminated / suspended employee ---------------------------
    if user.employment_status in INACTIVE_EMPLOYMENT_STATUSES:
        score += INACTIVE_EMPLOYEE_INCREASE
        factors.append({
            "factor": "Inactive employee account activity",
            "impact": INACTIVE_EMPLOYEE_INCREASE,
            "category": CRITICAL_SUSPICIOUS,
            "detail": (
                f"Employment status is '{user.employment_status}' but the "
                f"account performed activity"
            ),
        })

    # --- Rule 5: critical asset -------------------------------------------
    if asset is not None and asset.criticality_level == CRITICAL_ASSET_LABEL:
        score += CRITICAL_ASSET_INCREASE
        factors.append({
            "factor": "Critical asset access",
            "impact": CRITICAL_ASSET_INCREASE,
            "category": SUSPICIOUS,
            "detail": (
                f"Asset {asset.hostname} is classified as Critical "
                f"({asset.asset_type})"
            ),
        })

    # --- Rule 6: highly privileged action ----------------------------------
    privileged_factor = PRIVILEGED_EVENT_FACTORS.get(getattr(log, "event_type", ""))
    if privileged_factor:
        score += PRIVILEGED_ACTION_INCREASE
        factors.append({
            "factor": privileged_factor,
            "impact": PRIVILEGED_ACTION_INCREASE,
            "category": CRITICAL_SUSPICIOUS,
            "detail": f"Event type '{log.event_type}' is a highly privileged action",
        })

    # --- Rule 7: score boundaries -----------------------------------------
    adjusted = round(min(100.0, max(0.0, score)), 1)

    # --- Suppression decision ----------------------------------------------
    strong_legit = [f for f in factors if f["category"] == LEGITIMATE_STRONG]
    critical_suspicious = [f for f in factors if f["category"] == CRITICAL_SUSPICIOUS]
    is_inactive = user.employment_status in INACTIVE_EMPLOYMENT_STATUSES

    suppressed = (
        adjusted < SUPPRESSION_SCORE_THRESHOLD
        and bool(strong_legit)
        and not critical_suspicious
        and not is_inactive
    )

    if suppressed:
        reason = (
            f"Suppressed as likely false positive: context-adjusted risk "
            f"{adjusted:.1f} (below {SUPPRESSION_SCORE_THRESHOLD:.0f}) with "
            f"legitimate context ({', '.join(f['factor'] for f in strong_legit)}) "
            f"and no critical suspicious factors."
        )
    else:
        reasons = []
        if critical_suspicious:
            reasons.append(
                "critical suspicious factors present ("
                + ", ".join(f["factor"] for f in critical_suspicious) + ")"
            )
        if is_inactive:
            reasons.append("user is terminated or suspended")
        if adjusted >= SUPPRESSION_SCORE_THRESHOLD:
            reasons.append(f"adjusted risk {adjusted:.1f} is at or above the "
                           f"{SUPPRESSION_SCORE_THRESHOLD:.0f} suppression threshold")
        if not strong_legit:
            reasons.append("no strong legitimate context (weak departmental "
                           "alignment alone never suppresses an alert)")
        reason = f"Alert remains active: " + "; ".join(reasons) + "."

    explanation = _build_explanation(raw, adjusted, factors, suppressed)
    return {
        "raw_score": raw,
        "adjusted_score": adjusted,
        "delta": round(adjusted - raw, 1),
        "severity": severity_for_score(adjusted),
        "suppression_status": "Suppressed" if suppressed else "Active",
        "suppression_reason": reason,
        "factors": factors,
        "explanation": explanation,
        "matching_ticket": ticket,
    }


def _build_explanation(raw, adjusted, factors, suppressed):
    parts = [f"Raw ML risk score: {raw:.1f}."]
    if not factors:
        parts.append("No contextual adjustment factors applied.")
    for factor in factors:
        direction = "Risk reduced" if factor["impact"] < 0 else "Risk increased"
        parts.append(
            f"{direction} by {abs(factor['impact']):.0f} - {factor['factor']}: "
            f"{factor['detail']}."
        )
    parts.append(
        f"Final context-adjusted risk score: {adjusted:.1f}, classified as "
        f"{severity_for_score(adjusted)}."
    )
    if suppressed:
        parts.append("The alert was suppressed as a likely false positive because "
                     "legitimate operational context supports the activity.")
    else:
        parts.append("The alert remains active for SOC review.")
    return " ".join(parts)


def factors_to_json(factors):
    """Serialize contextual factors for storage in the alerts table."""
    return json.dumps(factors)


def factors_from_json(text):
    """Safely deserialize stored contextual factors (defensive on bad input)."""
    if not text:
        return []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [f for f in data if isinstance(f, dict) and "factor" in f]
    except (TypeError, ValueError):
        pass
    return []
