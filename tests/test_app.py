"""Automated tests for CE-UEBA (run against a temporary SQLite database)."""

import pytest
import secrets
from auth import set_password

import risk_engine
from app import create_app
from models import Alert, BehavioralLog, ChangeTicket, User, db
from seed_data import seed_database


@pytest.fixture()
def test_app(tmp_path):
    app = create_app({
        "TESTING": True,
        "SOC_ALLOWED_ROLES": {"IT Administrator"},
        "SOC_REVIEW_ROLES": {"IT Administrator"},
        "RATELIMIT_ENABLED": False,
        "WTF_CSRF_ENABLED": False,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///" + str(tmp_path / "ce_ueba_test.db"),
    })
    with app.app_context():
        db.drop_all()
        db.create_all()
        seed_database(verbose=False)
        user = User.query.filter_by(username="zeynep.arslan").one()
        app.config['TEST_PASSWORD'] = secrets.token_urlsafe(24)
        set_password(user, app.config['TEST_PASSWORD'], temporary=False)
        db.session.commit()
    return app


@pytest.fixture()
def client(test_app):
    client = test_app.test_client()
    assert client.post('/login', data={'identifier': 'zeynep.arslan',
        'password': test_app.config['TEST_PASSWORD']}).status_code == 302
    return client


# ------------------------------------------------------------- page tests --

def test_home_page_returns_200(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"CE-UEBA" in response.data


def test_dashboard_returns_200(client):
    response = client.get("/dashboard")
    assert response.status_code == 200


def test_existing_alert_page_returns_200(test_app, client):
    with test_app.app_context():
        alert_id = db.session.query(Alert.alert_id).first()[0]
    response = client.get(f"/alert/{alert_id}")
    assert response.status_code == 200


def test_unknown_alert_returns_404(client):
    response = client.get("/alert/999999")
    assert response.status_code == 404


def test_existing_user_page_returns_200(test_app, client):
    with test_app.app_context():
        user_id = db.session.query(User.user_id).first()[0]
    response = client.get(f"/user/{user_id}")
    assert response.status_code == 200


def test_unknown_user_returns_404(client):
    response = client.get("/user/999999")
    assert response.status_code == 404


def test_dashboard_json_endpoint_returns_valid_json(client):
    response = client.get("/api/dashboard-data")
    assert response.status_code == 200
    payload = response.get_json()
    assert isinstance(payload, dict)
    assert "summary" in payload
    assert "charts" in payload
    assert "raw_vs_adjusted" in payload["charts"]


# -------------------------------------------------------- risk engine tests --

def _scenario_a_parts(test_app):
    with test_app.app_context():
        user = User.query.filter_by(username="aylin.kaya").first()
        log = BehavioralLog.query.filter_by(
            user_id=user.user_id, event_type="software_deployment").first()
        tickets = ChangeTicket.query.filter_by(user_id=user.user_id).all()
        return user, log, tickets


def test_risk_scores_remain_within_bounds(test_app):
    with test_app.app_context():
        user = User.query.filter_by(username="mert.simsek").first()
        log = BehavioralLog.query.filter_by(
            user_id=user.user_id, event_type="privilege_escalation").first()
        tickets = ChangeTicket.query.filter_by(user_id=user.user_id).all()
        for raw in (-50.0, 0.0, 55.5, 99.9, 250.0):
            result = risk_engine.evaluate_alert(
                log=log, user=user, role=user.role,
                previous_role=user.previous_role, asset=log.asset,
                change_tickets=tickets, raw_ml_score=raw)
            assert 0.0 <= result["adjusted_score"] <= 100.0


def test_approved_change_context_lowers_risk(test_app):
    with test_app.app_context():
        user = User.query.filter_by(username="aylin.kaya").first()
        log = BehavioralLog.query.filter_by(
            user_id=user.user_id, event_type="software_deployment").first()
        tickets = ChangeTicket.query.filter_by(user_id=user.user_id).all()
        args = dict(log=log, user=user, role=user.role,
                    previous_role=user.previous_role, asset=log.asset,
                    raw_ml_score=82.0)
        with_ticket = risk_engine.evaluate_alert(change_tickets=tickets, **args)
        without_ticket = risk_engine.evaluate_alert(change_tickets=[], **args)
        assert with_ticket["adjusted_score"] < without_ticket["adjusted_score"]


def test_suspended_employee_activity_increases_risk(test_app):
    with test_app.app_context():
        user = User.query.filter_by(username="can.korkmaz").first()
        log = BehavioralLog.query.filter_by(
            user_id=user.user_id, event_type="bulk_export").first()
        args = dict(log=log, user=user, role=user.role,
                    previous_role=user.previous_role, asset=log.asset,
                    change_tickets=[], raw_ml_score=30.0)
        # Stay below the score ceiling so the employment-status impact is visible.
        suspended = risk_engine.evaluate_alert(**args)
        user.employment_status = "Active"  # in-memory change, not committed
        active = risk_engine.evaluate_alert(**args)
        assert suspended["adjusted_score"] > active["adjusted_score"]


def test_critical_suspicious_event_is_not_suppressed(test_app):
    with test_app.app_context():
        user = User.query.filter_by(username="can.korkmaz").first()
        log = BehavioralLog.query.filter_by(
            user_id=user.user_id, event_type="bulk_export").first()
        result = risk_engine.evaluate_alert(
            log=log, user=user, role=user.role,
            previous_role=user.previous_role, asset=log.asset,
            change_tickets=[], raw_ml_score=70.0)
        assert result["suppression_status"] == "Active"
        assert result["severity"] in ("High", "Critical")


# ----------------------------------------------------- analyst review tests --

def test_invalid_analyst_status_is_rejected(test_app, client):
    with test_app.app_context():
        alert = Alert.query.first()
        alert_id, original = alert.alert_id, alert.analyst_status

    response = client.post(f"/alerts/{alert_id}/review",
                           data={"analyst_status": "Escalated to the Moon"})
    assert response.status_code in (200, 302)

    with test_app.app_context():
        unchanged = db.session.get(Alert, alert_id)
        assert unchanged.analyst_status == original


def test_valid_analyst_status_is_applied(test_app, client):
    with test_app.app_context():
        alert_id = Alert.query.first().alert_id

    response = client.post(f"/alerts/{alert_id}/review",
                           data={"analyst_status": "Investigating"})
    assert response.status_code in (200, 302)

    with test_app.app_context():
        assert db.session.get(Alert, alert_id).analyst_status == "Investigating"
