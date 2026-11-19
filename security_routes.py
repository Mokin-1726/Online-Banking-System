"""
HTTP routes for the Suspicious Activity & Secure Confirmation module.

Customer
    /security/challenge/<tx_id>            the confirmation page (password -> OTP)
    /security/challenge/<tx_id>/password   POST  step 1
    /security/challenge/<tx_id>/otp        POST  step 2
    /security/challenge/<tx_id>/resend-otp POST
    /security/challenge/<tx_id>/cancel     POST
    /security/settings                     set / change the high-security password
    /security/notifications                security messages

Staff / Admin
    /staff/security-alerts                 alerts raised after repeated failures
    /staff/security-alerts/<id>/review     POST  mark an alert as reviewed
"""

from flask import (Blueprint, render_template, request, redirect, url_for,
                   session, flash)

import security_module as sec
from models import User, Account, Transaction
from utils import login_required, role_required, as_currency

bp = Blueprint("security", __name__)


def db():
    from app import get_db_connection
    return get_db_connection()


# ----------------------------------------------------------------------
# nav badges (used by base.html)
# ----------------------------------------------------------------------

@bp.app_context_processor
def inject_security_counts():
    counts = {"open_security_alerts": 0, "unread_security_notifications": 0}
    user_id, role = session.get("user_id"), session.get("role")
    if not user_id:
        return counts
    try:
        conn = db()
        try:
            if role in ("staff", "admin"):
                counts["open_security_alerts"] = sec.open_alert_count(conn)
            if role == "customer":
                counts["unread_security_notifications"] = sec.unread_count(conn, user_id)
        finally:
            conn.close()
    except Exception:
        pass   # a badge must never break a page
    return counts


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------

def _flash_event(event):
    if event == "password_timeout":
        flash("Confirmation failed. You did not enter the high-security password within "
              f"{sec.PASSWORD_WINDOW_SECONDS} seconds. This attempt was recorded for security monitoring.",
              "error")
    elif event == "otp_expired":
        flash("OTP verification failed. The OTP has expired. Request a new OTP to continue.", "error")


def _load(conn, tx_id):
    """Load the customer's own challenge (row-locked) and apply the time rules."""
    ch = sec.get_challenge(conn, tx_id, session["user_id"], lock=True)
    if not ch:
        return None, None
    event = sec.enforce_timeouts(conn, ch)
    return ch, event


def _send_otp(conn, ch):
    otp = sec.issue_otp(conn, ch)
    if sec.DEMO_SHOW_OTP:
        flash(f"DEMO MODE — no SMS gateway is connected, so your OTP is shown here: {otp}", "success")
    else:
        flash("An OTP has been sent to your registered mobile number or email.", "success")


def _attempts_text(ch):
    return (f"{ch['failed_attempts']} failed attempt(s). The transfer is blocked once failures "
            f"go above {sec.MAX_FAILED_ATTEMPTS}.")


def _page(conn, ch):
    p = sec.tx_parties(conn, ch["transaction_id"])
    return render_template(
        "security_challenge.html",
        ch=ch, parties=p, reasons=sec.get_reasons(ch), as_currency=as_currency,
        mask=sec.mask_account,
        has_password=sec.has_high_security_password(conn, ch["user_id"]),
        password_seconds_left=sec.seconds_left(ch["password_deadline"]),
        otp_seconds_left=sec.seconds_left(ch["otp_expires_at"]),
        otp_active=bool(ch["otp_hash"]),
        attempts_text=_attempts_text(ch),
        window=sec.PASSWORD_WINDOW_SECONDS, max_failed=sec.MAX_FAILED_ATTEMPTS,
    )


def _back_to(tx_id):
    return redirect(url_for("security.challenge", tx_id=tx_id))


# ----------------------------------------------------------------------
# Customer: the confirmation flow
# ----------------------------------------------------------------------

@bp.route("/security/challenge/<int:tx_id>")
@login_required
def challenge(tx_id):
    conn = db()
    try:
        ch, event = _load(conn, tx_id)
        if not ch:
            flash("No pending security confirmation was found for that transfer.", "error")
            return redirect(url_for("routes.dashboard"))
        _flash_event(event)
        return _page(conn, ch)
    finally:
        conn.close()


@bp.route("/security/challenge/<int:tx_id>/password", methods=["POST"])
@login_required
def submit_password(tx_id):
    conn = db()
    try:
        ch, event = _load(conn, tx_id)
        if not ch:
            return redirect(url_for("routes.dashboard"))
        if event:
            _flash_event(event)
            return _back_to(tx_id)
        if ch["status"] != "password_pending":
            return _back_to(tx_id)

        if not sec.has_high_security_password(conn, ch["user_id"]):
            flash("You have not set a high-security password yet. Set one first, then come back "
                  "to this page to finish your transfer.", "error")
            return redirect(url_for("security.settings", next=tx_id))

        password = request.form.get("hs_password", "")
        if sec.verify_high_security_password(conn, ch["user_id"], password):
            sec.log_attempt(conn, ch["id"], "password", "success")
            _send_otp(conn, ch)
            flash("High-security password accepted. Now enter the OTP.", "success")
        else:
            blocked = sec.register_failure(conn, ch, "password", "wrong")
            if not blocked:
                flash("Incorrect high-security password. This attempt was recorded. "
                      f"You have {sec.PASSWORD_WINDOW_SECONDS} seconds for the next try.", "error")
        return _back_to(tx_id)
    finally:
        conn.close()


@bp.route("/security/challenge/<int:tx_id>/otp", methods=["POST"])
@login_required
def submit_otp(tx_id):
    # imported here so routes.py can import this package's helpers without a cycle
    from routes import _execute_transfer

    conn = db()
    try:
        ch, event = _load(conn, tx_id)
        if not ch:
            return redirect(url_for("routes.dashboard"))
        if event:
            _flash_event(event)
            return _back_to(tx_id)
        if ch["status"] != "otp_pending":
            return _back_to(tx_id)
        if not ch["otp_hash"]:
            flash("There is no active OTP. Request a new one.", "error")
            return _back_to(tx_id)

        otp = request.form.get("otp", "").strip()
        if not sec.verify_otp(conn, ch, otp):
            blocked = sec.register_failure(conn, ch, "otp", "wrong")
            if not blocked:
                flash("OTP verification failed. The OTP entered is incorrect. "
                      "Repeated failed attempts will block this transfer.", "error")
            return _back_to(tx_id)

        # Both checks passed -> move the money, exactly once.
        sec.log_attempt(conn, ch["id"], "otp", "success")
        if not sec.claim_approval(conn, ch):
            return _back_to(tx_id)

        tx = Transaction.find_by_id(conn, ch["transaction_id"])
        sender = Account.find_by_id(conn, tx.sender_id)
        receiver = Account.find_by_id(conn, tx.receiver_id)
        try:
            _execute_transfer(conn, sender, receiver, tx.amount)
        except ValueError:
            sec.finish_failed_transfer(conn, ch)
            flash("Transfer can't be completed: insufficient balance.", "error")
            return redirect(url_for("routes.dashboard"))

        sec.mark_transfer_confirmed(conn, ch)
        flash(f"Secure confirmation passed. Transfer of {as_currency(tx.amount)} completed.", "success")
        return redirect(url_for("routes.dashboard"))
    finally:
        conn.close()


@bp.route("/security/challenge/<int:tx_id>/resend-otp", methods=["POST"])
@login_required
def resend_otp(tx_id):
    conn = db()
    try:
        ch, event = _load(conn, tx_id)
        if not ch:
            return redirect(url_for("routes.dashboard"))
        if event:
            _flash_event(event)
        if ch["status"] == "otp_pending":
            _send_otp(conn, ch)
        return _back_to(tx_id)
    finally:
        conn.close()


@bp.route("/security/challenge/<int:tx_id>/cancel", methods=["POST"])
@login_required
def cancel(tx_id):
    conn = db()
    try:
        ch, _ = _load(conn, tx_id)
        if ch and sec.cancel_challenge(conn, ch):
            flash("Transfer cancelled. No money was sent.", "success")
        return redirect(url_for("routes.transfer"))
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Customer: high-security password + notifications
# ----------------------------------------------------------------------

@bp.route("/security/settings", methods=["GET", "POST"])
@role_required("customer")
def settings():
    conn = db()
    try:
        user = User.find_by_id(conn, session["user_id"])
        next_tx = request.values.get("next", type=int)

        if request.method == "POST":
            login_password = request.form.get("login_password", "")
            new = request.form.get("new_password", "")
            confirm = request.form.get("confirm_password", "")

            error = None
            if not user.check_password(login_password):
                error = "Your login password is incorrect."
            elif new != confirm:
                error = "The two new passwords do not match."
            elif user.check_password(new):
                error = "The high-security password must be different from your login password."
            else:
                error = sec.validate_high_security_password(new)

            if error:
                flash(error, "error")
            else:
                sec.set_high_security_password(conn, user.id, new)
                flash("Your high-security password has been saved.", "success")
                if next_tx and sec.get_challenge(conn, next_tx, user.id):
                    return redirect(url_for("security.challenge", tx_id=next_tx))
                return redirect(url_for("security.settings"))

        return render_template("security_settings.html",
                               is_set=sec.has_high_security_password(conn, user.id),
                               next_tx=next_tx, window=sec.PASSWORD_WINDOW_SECONDS)
    finally:
        conn.close()


@bp.route("/security/notifications")
@role_required("customer")
def notifications():
    conn = db()
    try:
        items = sec.list_notifications(conn, session["user_id"])
        sec.mark_all_read(conn, session["user_id"])
        return render_template("security_notifications.html", items=items)
    finally:
        conn.close()


# ----------------------------------------------------------------------
# Staff / Admin: alerts
# ----------------------------------------------------------------------

@bp.route("/staff/security-alerts")
@role_required("staff", "admin")
def staff_alerts():
    conn = db()
    try:
        show = request.args.get("show", "open")
        alerts = sec.list_alerts(conn, only_open=(show != "all"))
        return render_template("staff_security_alerts.html", alerts=alerts, show=show,
                               as_currency=as_currency)
    finally:
        conn.close()


@bp.route("/staff/security-alerts/<int:alert_id>/review", methods=["POST"])
@role_required("staff", "admin")
def review_alert(alert_id):
    conn = db()
    try:
        if sec.mark_alert_reviewed(conn, alert_id, session["user_id"]):
            flash("Alert marked as reviewed.", "success")
        return redirect(url_for("security.staff_alerts"))
    finally:
        conn.close()