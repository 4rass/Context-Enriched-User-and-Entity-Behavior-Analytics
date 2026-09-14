"""CE-UEBA Flask application (academic proof of concept)."""

import os
from datetime import datetime

from flask import (Flask, abort, flash, jsonify, redirect, render_template,
                   request, url_for)
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException

import risk_engine
from models import (Alert, BehavioralLog, ChangeTicket, Role, User, db)

csrf = CSRFProtect()

# Whitelists used to validate query parameters and form input.
VALID_ANALYST_STATUSES = {"Open", "Investigating", "Closed as Benign", "Confirmed Threat"}
VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}
VALID_SUPPRESSION_STATUSES = {"Active", "Suppressed"}

# Development-only fallback; the README documents setting CE_UEBA_SECRET_KEY.
DEV_SECRET_KEY = "dev-only-insecure-secret-key-change-me"

DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self' https://cdn.jsdelivr.net; "
    "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
    "img-src 'self' data:; "
    "font-src 'self' https://cdn.jsdelivr.net; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'"
)


def create_app(config_overrides=None):
    """Application factory."""
    app = Flask(__name__)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.update(
        SECRET_KEY=os.environ.get("CE_UEBA_SECRET_KEY", DEV_SECRET_KEY),
        SQLALCHEMY_DATABASE_URI=os.environ.get(
            "CE_UEBA_DATABASE_URI",
            "sqlite:///" + os.path.join(app.instance_path, "ce_ueba.db"),
        ),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,  # 1 MB request cap
    )
    if config_overrides:
        app.config.update(config_overrides)

    db.init_app(app)
    csrf.init_app(app)

    with app.app_context():
        db.create_all()

    _register_routes(app)
    _register_error_handlers(app)
    _register_security_headers(app)
    return app


# ---------------------------------------------------------------- filters --

def _filtered_alerts():
    """Return alerts matching the dashboard filter query parameters.

    All parameter values are validated against whitelists; anything invalid
    is ignored rather than injected into the query. Only ORM expressions are
    used (no raw SQL string assembly).
    """
    query = (
        Alert.query
        .join(User, Alert.user_id == User.user_id)
        .join(BehavioralLog, Alert.log_id == BehavioralLog.log_id)
    )

    severity = request.args.get("severity", "").strip()
    if severity in VALID_SEVERITIES:
        query = query.filter(Alert.severity == severity)

    suppression = request.args.get("suppression", "").strip()
    if suppression in VALID_SUPPRESSION_STATUSES:
        query = query.filter(Alert.suppression_status == suppression)

    department = request.args.get("department", "").strip()
    if department:
        query = query.filter(User.department == department)

    event_type = request.args.get("event_type", "").strip()
    if event_type:
        query = query.filter(BehavioralLog.event_type == event_type)

    return query.order_by(Alert.created_at.desc()).all()


def _filter_options():
    departments = sorted({row[0] for row in db.session.query(User.department).distinct()
                          if row[0]})
    event_types = sorted({row[0] for row in db.session.query(BehavioralLog.event_type).distinct()
                          if row[0]})
    return departments, event_types


def _summary_for(alerts):
    total = len(alerts)
    suppressed = sum(1 for a in alerts if a.suppression_status == "Suppressed")
    active_high = sum(1 for a in alerts
                      if a.suppression_status == "Active" and a.severity in ("High", "Critical"))
    pct = round(suppressed / total * 100.0, 1) if total else 0.0
    avg_raw = round(sum(a.raw_ml_risk_score for a in alerts) / total, 1) if total else 0.0
    avg_adj = round(sum(a.context_adjusted_risk_score for a in alerts) / total, 1) if total else 0.0
    return {
        "total_anomalies": total,
        "suppressed_false_positives": suppressed,
        "suppression_percentage": pct,
        "active_high_risk_threats": active_high,
        "average_raw_risk_score": avg_raw,
        "average_adjusted_risk_score": avg_adj,
    }


# ------------------------------------------------------------------ routes --

def _register_routes(app):

    @app.route("/")
    def index():
        return render_template("index.html")

    @app.route("/dashboard")
    def dashboard():
        alerts = _filtered_alerts()
        departments, event_types = _filter_options()
        summary = _summary_for(alerts)
        return render_template(
            "dashboard.html",
            alerts=alerts,
            summary=summary,
            departments=departments,
            event_types=event_types,
        )

    @app.route("/alert/<int:alert_id>")
    def alert_details(alert_id):
        alert = db.session.get(Alert, alert_id)
        if alert is None:
            abort(404)

        log = alert.log
        user = alert.user
        asset = log.asset

        tickets = []
        matching_ticket = None
        if asset is not None:
            tickets = (ChangeTicket.query
                       .filter_by(user_id=user.user_id, asset_id=asset.asset_id)
                       .order_by(ChangeTicket.approved_start.desc())
                       .all())
            matching_ticket = risk_engine.find_matching_ticket(log, user, asset, tickets)

        factors = risk_engine.factors_from_json(alert.context_factors)
        delta = round(alert.context_adjusted_risk_score - alert.raw_ml_risk_score, 1)

        return render_template(
            "alert_details.html",
            alert=alert,
            log=log,
            user=user,
            role=user.role,
            previous_role=user.previous_role,
            asset=asset,
            tickets=tickets,
            matching_ticket=matching_ticket,
            factors=factors,
            delta=delta,
            analyst_statuses=sorted(VALID_ANALYST_STATUSES),
        )

    @app.route("/users")
    def users():
        rows = []
        for user in User.query.order_by(User.full_name).all():
            alert_count = Alert.query.filter_by(user_id=user.user_id).count()
            rows.append({"user": user, "alert_count": alert_count})
        return render_template("users.html", rows=rows)

    @app.route("/user/<int:user_id>")
    def user_profile(user_id):
        user = db.session.get(User, user_id)
        if user is None:
            abort(404)

        logs = (BehavioralLog.query
                .filter_by(user_id=user.user_id)
                .order_by(BehavioralLog.timestamp.desc())
                .limit(15)
                .all())
        tickets = (ChangeTicket.query
                   .filter_by(user_id=user.user_id)
                   .order_by(ChangeTicket.approved_start.desc())
                   .all())
        alerts = (Alert.query
                  .filter_by(user_id=user.user_id)
                  .order_by(Alert.created_at.desc())
                  .all())

        asset_map = {}
        for log in logs:
            if log.asset is not None:
                asset_map[log.asset.asset_id] = log.asset
        for ticket in tickets:
            if ticket.asset is not None:
                asset_map[ticket.asset.asset_id] = ticket.asset

        count = len(alerts)
        avg_raw = (round(sum(a.raw_ml_risk_score for a in alerts) / count, 1)
                   if count else None)
        avg_adj = (round(sum(a.context_adjusted_risk_score for a in alerts) / count, 1)
                   if count else None)
        suppressed_count = sum(1 for a in alerts if a.suppression_status == "Suppressed")

        return render_template(
            "user_profile.html",
            user=user,
            role=user.role,
            previous_role=user.previous_role,
            logs=logs,
            tickets=tickets,
            alerts=alerts,
            assets=sorted(asset_map.values(), key=lambda a: a.hostname),
            avg_raw=avg_raw,
            avg_adjusted=avg_adj,
            suppressed_count=suppressed_count,
            alert_count=count,
        )

    @app.route("/alerts/<int:alert_id>/review", methods=["POST"])
    def review_alert(alert_id):
        alert = db.session.get(Alert, alert_id)
        if alert is None:
            abort(404)

        status = request.form.get("analyst_status", "").strip()
        if status not in VALID_ANALYST_STATUSES:
            # Reject arbitrary values; never trust the client-side select list.
            flash("Invalid analyst status submitted. Allowed values: "
                  f"{', '.join(sorted(VALID_ANALYST_STATUSES))}.", "danger")
        else:
            alert.analyst_status = status
            db.session.commit()
            flash(f"Alert #{alert.alert_id} marked as '{status}'.", "success")
        return redirect(url_for("alert_details", alert_id=alert_id))

    @app.route("/api/dashboard-data")
    def dashboard_data():
        alerts = _filtered_alerts()
        summary = _summary_for(alerts)

        chronological = sorted(alerts, key=lambda a: a.alert_id)
        severity_labels = ["Critical", "High", "Medium", "Low"]
        severity_counts = [sum(1 for a in alerts if a.severity == label)
                           for label in severity_labels]

        dept_counts = {}
        for alert in alerts:
            dept_counts[alert.user.department] = \
                dept_counts.get(alert.user.department, 0) + 1

        return jsonify({
            "summary": summary,
            "charts": {
                "raw_vs_adjusted": {
                    "labels": [f"#{a.alert_id}" for a in chronological],
                    "raw_scores": [a.raw_ml_risk_score for a in chronological],
                    "adjusted_scores": [a.context_adjusted_risk_score for a in chronological],
                },
                "severity_breakdown": {
                    "labels": severity_labels,
                    "counts": severity_counts,
                },
                "suppression_breakdown": {
                    "labels": ["Active", "Suppressed"],
                    "counts": [
                        sum(1 for a in alerts if a.suppression_status == "Active"),
                        sum(1 for a in alerts if a.suppression_status == "Suppressed"),
                    ],
                },
                "department_breakdown": {
                    "labels": sorted(dept_counts.keys()),
                    "counts": [dept_counts[d] for d in sorted(dept_counts.keys())],
                },
            },
        })


# ------------------------------------------------------------------ errors --

def _register_error_handlers(app):

    @app.errorhandler(404)
    def not_found(error):
        return render_template(
            "error.html", code=404,
            message="The page or record you requested was not found."), 404

    @app.errorhandler(500)
    def server_error(error):
        # Never leak stack traces to the client.
        return render_template(
            "error.html", code=500,
            message="An unexpected error occurred. Please try again later."), 500

    @app.errorhandler(HTTPException)
    def handle_http_exception(error):
        code = error.code or 500
        return render_template(
            "error.html", code=code,
            message=error.description or "Unexpected error"), code

    @app.errorhandler(Exception)
    def handle_unexpected(error):
        # Last-resort guard so no stack trace reaches the browser.
        return render_template(
            "error.html", code=500,
            message="An unexpected error occurred. Please try again later."), 500


# ----------------------------------------------------------------- headers --

def _register_security_headers(app):

    @app.after_request
    def set_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers["Content-Security-Policy"] = DEFAULT_CSP
        response.headers.setdefault("Cache-Control", "no-store")
        return response


application = create_app()

if __name__ == "__main__":
    # Debug mode is OFF by default; enable with FLASK_DEBUG=1 for development.
    # Port 5000 is used by AirPlay Receiver on macOS.
    application.run(host="127.0.0.1", port=5001,
                    debug=os.environ.get("FLASK_DEBUG") == "1")
