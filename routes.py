"""
All HTTP routes for Ledgerline, grouped on a single Blueprint.

Each view opens its own MySQL connection from the pool (see app.py) and
closes it before returning, so connections never leak across requests.
"""

from datetime import datetime
from decimal import Decimal, InvalidOperation

from flask import (
    Blueprint, render_template, request, redirect, url_for,
    session, flash, jsonify, send_file
)

from models import User, Admin, Staff, Customer, Account, Transaction, RiskAnalyzer, Feedback
from utils import (login_required, role_required, as_currency, hash_password, humanize_minutes,
                   normalize_phone, normalize_upi, make_upi_id)
import services
import security_module as sec   # suspicious-activity detection + secure confirmation

bp = Blueprint("routes", __name__)


def db():
    """Import here (not at module scope) to avoid a circular import with app.py."""
    from app import get_db_connection
    return get_db_connection()


# ======================================================================
# Home / setup
# ======================================================================

@bp.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("routes.dashboard"))
    return redirect(url_for("routes.login"))


@bp.route("/setup-admin", methods=["GET", "POST"])
def setup_admin():
    """One-time bootstrap route. Disappears (returns 403) the moment an
    Admin exists — this is what enforces the singleton-admin rule at
    the account-creation boundary, on top of the DB-level check in
    Admin.bootstrap()."""
    conn = db()
    try:
        if User.admin_exists(conn):
            flash("An Admin account already exists. This setup page is disabled.", "error")
            return redirect(url_for("routes.admin_login"))

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            if not name or not email or not password:
                flash("All fields are required.", "error")
                return render_template("setup_admin.html")
            if password != confirm:
                flash("Passwords do not match.", "error")
                return render_template("setup_admin.html")
            if len(password) < 8:
                flash("Password must be at least 8 characters.", "error")
                return render_template("setup_admin.html")

            try:
                Admin.bootstrap(conn, name, email, password)
                flash("Admin account created. You can now log in.", "success")
                return redirect(url_for("routes.admin_login"))
            except ValueError as e:
                flash(str(e), "error")
                return render_template("setup_admin.html")

        return render_template("setup_admin.html")
    finally:
        conn.close()


# ======================================================================
# Auth
# ======================================================================

@bp.route("/register", methods=["GET", "POST"])
def register():
    conn = db()
    try:
        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            phone = request.form.get("phone", "").strip()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")

            def again(msg):
                flash(msg, "error")
                return render_template("register.html", form=request.form)

            if not name or not email or not phone or not password:
                return again("All fields are required.")
            if not normalize_phone(phone):
                return again("Enter a valid 10-digit mobile number.")
            if password != confirm:
                return again("Passwords do not match.")
            if len(password) < 8:
                return again("Password must be at least 8 characters.")

            try:
                user = Customer.register(conn, name, email, password, phone)
                flash(f"Account created. Your UPI IDs: {user.upi_id} and {user.upi_email}. Please log in.", "success")
                return redirect(url_for("routes.login"))
            except ValueError as e:
                return again(str(e))

        return render_template("register.html", form={})
    finally:
        conn.close()


@bp.before_request
def _block_closed_accounts():
    """If someone's account is closed while they're logged in, end their
    session on the very next request."""
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = db()
    try:
        cur = conn.cursor()
        cur.execute("SELECT is_active FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        cur.close()
    finally:
        conn.close()
    if row is None or not row[0]:
        session.clear()
        flash("This account has been closed.", "error")
        return redirect(url_for("routes.login"))
    return None


def _attempt_login(conn, email, password, allowed_roles):
    """Shared authentication core for all three login routes. Returns
    (user, error_message) — error_message is None on success. Doesn't
    reveal whether an email exists at all; it only distinguishes "wrong
    credentials" from "right credentials, wrong login page" once the
    password has actually checked out, so a stranger probing /admin/login
    with a customer's email still just gets "invalid credentials"."""
    user = User.find_by_email(conn, email)
    if not (user and user.check_password(password)):
        return None, "Invalid email or password."
    if not user.is_active:
        return None, "This account has been closed."
    if user.role not in allowed_roles:
        return None, "This login page isn't for your account type."
    return user, None


def _log_in_user(user):
    session.permanent = True
    session["user_id"] = user.id
    session["name"] = user.name
    session["role"] = user.role


_DASHBOARD_BY_ROLE = {
    "customer": "routes.dashboard",
    "staff": "routes.staff_dashboard",
    "admin": "routes.admin_dashboard",
}


_LOGIN_TABS = ("customer", "staff", "admin")


def _login_view(default_tab):
    """One login page with three tabs: Customer, Staff and Admin.

    The tab is sent as a hidden `login_type` field, and each tab accepts
    only its own role. After a successful login the user lands on the
    dashboard for their role.
    """
    tab = request.args.get("tab", default_tab)
    if tab not in _LOGIN_TABS:
        tab = default_tab

    if request.method == "POST":
        tab = request.form.get("login_type", default_tab)
        if tab not in _LOGIN_TABS:
            tab = default_tab
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = db()
        try:
            user, error = _attempt_login(conn, email, password, {tab})
            if user:
                User.record_login(conn, user.id)   # feeds the login calendar
        finally:
            conn.close()

        if error:
            if error.startswith("This login page"):
                error = "This tab isn't for your account type. Please pick the right tab."
            flash(error, "error")
            return render_template("login.html", active_tab=tab)

        _log_in_user(user)
        flash(f"Welcome back, {user.name}.", "success")
        return redirect(url_for(_DASHBOARD_BY_ROLE[user.role]))

    return render_template("login.html", active_tab=tab)


@bp.route("/login", methods=["GET", "POST"])
def login():
    return _login_view("customer")


# Old URLs still work (logout redirects, bookmarks) and open the same
# page with the matching tab selected.
@bp.route("/staff/login", methods=["GET", "POST"])
def staff_login():
    return _login_view("staff")


@bp.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    return _login_view("admin")


@bp.route("/logout")
def logout():
    role = session.get("role")
    session.clear()
    flash("You have been logged out.", "success")
    if role == "staff":
        return redirect(url_for("routes.staff_login"))
    if role == "admin":
        return redirect(url_for("routes.admin_login"))
    return redirect(url_for("routes.login"))


@bp.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        conn = db()
        try:
            user = User.find_by_id(conn, session["user_id"])

            if not user.check_password(old_password):
                flash("Your current password is incorrect.", "error")
                return render_template("change_password.html")
            if new_password != confirm_password:
                flash("New passwords do not match.", "error")
                return render_template("change_password.html")
            if len(new_password) < 8:
                flash("New password must be at least 8 characters.", "error")
                return render_template("change_password.html")

            User.update_password(conn, user.id, hash_password(new_password))
            flash("Password updated.", "success")
            return redirect(url_for("routes.dashboard"))
        finally:
            conn.close()

    return render_template("change_password.html")


# ======================================================================
# Dashboard / account
# ======================================================================

@bp.route("/dashboard")
@login_required
def dashboard():
    if session.get("role") == "staff":
        return redirect(url_for("routes.staff_dashboard"))
    if session.get("role") == "admin":
        return redirect(url_for("routes.admin_dashboard"))

    conn = db()
    try:
        user = User.find_by_id(conn, session["user_id"])
        accounts = Account.find_by_user(conn, user.id)
        recent = []
        if accounts:
            recent = Transaction.for_account(conn, accounts[0].id)[:5]
        return render_template(
            "dashboard.html", user=user, accounts=accounts, recent=recent,
            as_currency=as_currency,
            login_heatmap=services.get_login_activity(conn, user.id),
        )
    finally:
        conn.close()


@bp.route("/account")
@login_required
def account_details():
    conn = db()
    try:
        user = User.find_by_id(conn, session["user_id"])
        accounts = Account.find_by_user(conn, user.id)
        return render_template("account.html", user=user, accounts=accounts,
                                as_currency=as_currency)
    finally:
        conn.close()


@bp.route("/profile", methods=["GET", "POST"])
@role_required("customer")
def profile():
    """Customer edits their own details. The UPI ID is created from the
    phone number, so saving a (new) phone number (re)creates the UPI ID."""
    conn = db()
    try:
        user = User.find_by_id(conn, session["user_id"])
        accounts = Account.find_by_user(conn, user.id)

        if request.method == "POST":
            name = request.form.get("name", "").strip()
            email = request.form.get("email", "").strip().lower()
            phone = request.form.get("phone", "").strip()
            old_upis = (user.upi_id, user.upi_email)
            try:
                user = User.update_profile(conn, user.id, name, email, phone)
                session["name"] = user.name
                if (user.upi_id, user.upi_email) != old_upis:
                    ids = " and ".join(x for x in (user.upi_id, user.upi_email) if x)
                    flash(f"Profile updated. Your UPI IDs: {ids}.", "success")
                else:
                    flash("Profile updated.", "success")
                return redirect(url_for("routes.profile"))
            except ValueError as e:
                flash(str(e), "error")
                # keep what they typed, show saved values for everything else
                return render_template("profile.html", user=user, accounts=accounts,
                                       form=request.form, as_currency=as_currency)

        return render_template("profile.html", user=user, accounts=accounts,
                               form={}, as_currency=as_currency)
    finally:
        conn.close()


# ======================================================================
# Transfers (with fraud detection)
# ======================================================================

def _resolve_receiver(conn, method, value):
    """Find the receiving account from an account number, a UPI ID or a
    phone number. Returns (account, owner, reference, error)."""
    if method == "upi":
        upi = normalize_upi(value)
        owner = User.find_by_upi(conn, upi) if upi else None
        if not owner or owner.role != "customer" or not owner.is_active:
            return None, None, None, "No account found with that UPI ID."
        ref = upi
    elif method == "phone":
        phone = normalize_phone(value)
        if not phone:
            return None, None, None, "Enter a valid 10-digit mobile number."
        owner = User.find_by_phone(conn, phone)
        if not owner or owner.role != "customer" or not owner.is_active:
            return None, None, None, "No account is registered with that phone number."
        ref = phone
    else:
        account = Account.find_by_account_number(conn, value.strip())
        if not account:
            return None, None, None, "No account found with that account number."
        owner = User.find_by_id(conn, account.user_id)
        if owner and not owner.is_active:
            return None, None, None, "No account found with that account number."
        return account, owner, account.account_number, None

    receiver_accounts = Account.find_by_user(conn, owner.id)
    if not receiver_accounts:
        return None, None, None, "That customer has no account to receive money."
    return receiver_accounts[0], owner, ref, None


@bp.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    conn = db()
    try:
        user = User.find_by_id(conn, session["user_id"])
        accounts = Account.find_by_user(conn, user.id)
        if not accounts:
            flash("No account found for this user.", "error")
            return redirect(url_for("routes.dashboard"))
        sender_account = accounts[0]

        def page(**extra):
            return render_template("transfer.html", account=sender_account,
                                   as_currency=as_currency, user=user,
                                   form=request.form, **extra)

        if request.method == "POST":
            method = request.form.get("method", "account")
            if method not in ("account", "upi", "phone"):
                method = "account"
            # `receiver` is the new field name; `receiver_account` kept for old forms
            receiver_value = (request.form.get("receiver")
                              or request.form.get("receiver_account", "")).strip()
            amount_raw = request.form.get("amount", "").strip()

            try:
                amount = Decimal(amount_raw)
            except (InvalidOperation, ValueError):
                flash("Enter a valid amount.", "error")
                return page()

            if amount <= 0:
                flash("Transfer amount must be greater than zero.", "error")
                return page()

            receiver_account, receiver_owner, receiver_ref, error = _resolve_receiver(
                conn, method, receiver_value)
            if error:
                flash(error, "error")
                return page()
            if receiver_account.id == sender_account.id:
                flash("You can't transfer to your own account.", "error")
                return page()

            analyzer = RiskAnalyzer(conn)
            score, factors = analyzer.analyze(sender_account, receiver_account, amount)

            # Suspicious-activity module: compare with the customer's normal behaviour
            # and add its own explainable factors on top of the rule-based score.
            assessment = sec.assess(conn, sender_account, receiver_account, amount, score, factors)
            score, factors = assessment["score"], assessment["factors"]
            decision = analyzer.decision_for(score)

            def record(status):
                return Transaction.create(conn, sender_account.id, receiver_account.id,
                                          amount, score, status,
                                          transfer_method=method, receiver_ref=receiver_ref)

            insufficient = any(f["code"] == "INSUFFICIENT_BALANCE" for f in factors)
            hard_block = insufficient or (decision == "blocked" and not sec.STEP_UP_FOR_HIGH_RISK)

            if hard_block:
                # can't pay at all (or high risk with step-up switched off) -> refuse outright
                tx = record("blocked")
                analyzer.log(tx.id, factors, score)
                return page(blocked=True, risk_score=score, factors=factors, tips=RiskAnalyzer.TIPS)

            if assessment["suspicious"]:
                # hold the transfer and ask for: high-security password (60 s) -> OTP
                tx = record("warned")
                analyzer.log(tx.id, factors, score)
                sec.open_challenge(conn, tx.id, user.id, assessment)
                flash("Suspicious activity detected. Your transfer is on hold until you complete "
                      "secure confirmation.", "error")
                return redirect(url_for("security.challenge", tx_id=tx.id))

            # decision == "allowed" -> execute immediately
            _execute_transfer(conn, sender_account, receiver_account, amount)
            tx = record("allowed")
            analyzer.log(tx.id, factors, score)
            who = receiver_owner.name if receiver_owner else receiver_account.account_number
            flash(f"Transfer of {as_currency(amount)} to {who} completed.", "success")
            return redirect(url_for("routes.dashboard"))

        return render_template("transfer.html", account=sender_account, user=user,
                               as_currency=as_currency, form={})
    finally:
        conn.close()


@bp.route("/transfer/confirm/<int:tx_id>", methods=["POST"])
@login_required
def confirm_transfer(tx_id):
    """Old one-click confirmation. A held transfer can now only be released by the
    secure-confirmation flow (high-security password + OTP), so this just sends
    the customer there — it can no longer be used to skip the checks."""
    return redirect(url_for("security.challenge", tx_id=tx_id))


def _execute_transfer(conn, sender_account, receiver_account, amount):
    """Moves money between two accounts as a single DB transaction.
    Re-checks balance under the DB's own lock to avoid a race between
    the earlier risk check and this write."""
    cur = conn.cursor()
    try:
        cur.execute("SELECT balance FROM accounts WHERE id = %s FOR UPDATE", (sender_account.id,))
        current_balance = cur.fetchone()[0]
        if Decimal(str(current_balance)) < amount:
            raise ValueError("Insufficient balance.")

        cur.execute("UPDATE accounts SET balance = balance - %s WHERE id = %s",
                     (amount, sender_account.id))
        cur.execute("UPDATE accounts SET balance = balance + %s WHERE id = %s",
                     (amount, receiver_account.id))
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()


# ======================================================================
# Statements
# ======================================================================

@bp.route("/history")
@login_required
def history():
    conn = db()
    try:
        user = User.find_by_id(conn, session["user_id"])
        accounts = Account.find_by_user(conn, user.id)
        if not accounts:
            return render_template("history.html", transactions=[], account=None,
                                    as_currency=as_currency)
        account = accounts[0]

        start_date = request.args.get("start_date") or None
        end_date = request.args.get("end_date") or None
        transactions = Transaction.for_account(conn, account.id, start_date, end_date)

        return render_template(
            "history.html", transactions=transactions, account=account,
            as_currency=as_currency, start_date=start_date, end_date=end_date,
        )
    finally:
        conn.close()


@bp.route("/history/pdf")
@login_required
def history_pdf():
    conn = db()
    try:
        user = User.find_by_id(conn, session["user_id"])
        accounts = Account.find_by_user(conn, user.id)
        if not accounts:
            flash("No account found to generate a statement for.", "error")
            return redirect(url_for("routes.history"))
        account = accounts[0]

        start_date = request.args.get("start_date") or None
        end_date = request.args.get("end_date") or None
        transactions = Transaction.for_account(conn, account.id, start_date, end_date)

        pdf_buffer = services.generate_pdf_statement(account, transactions, start_date, end_date)
        filename = f"ledgerline-statement-{account.account_number}.pdf"
        return send_file(pdf_buffer, mimetype="application/pdf",
                          as_attachment=True, download_name=filename)
    finally:
        conn.close()


@bp.route("/api/trends")
@login_required
def api_trends():
    """Last 14 days of outgoing-transfer totals for the current user's
    account — feeds the small trend chart on the dashboard."""
    conn = db()
    try:
        user = User.find_by_id(conn, session["user_id"])
        accounts = Account.find_by_user(conn, user.id)
        if not accounts:
            return jsonify({"labels": [], "values": []})
        account = accounts[0]

        cur = conn.cursor(dictionary=True)
        cur.execute(
            """SELECT DATE(`timestamp`) AS day, SUM(amount) AS total
               FROM transactions
               WHERE sender_id = %s AND status IN ('allowed', 'confirmed')
                 AND `timestamp` >= DATE_SUB(CURDATE(), INTERVAL 14 DAY)
               GROUP BY DATE(`timestamp`)
               ORDER BY day ASC""",
            (account.id,),
        )
        rows = cur.fetchall()
        cur.close()

        labels = [str(r["day"]) for r in rows]
        values = [float(r["total"]) for r in rows]
        return jsonify({"labels": labels, "values": values})
    finally:
        conn.close()


@bp.route("/feedback", methods=["GET", "POST"])
@role_required("customer")
def feedback():
    conn = db()
    try:
        if request.method == "POST":
            feedback_type = request.form.get("type", "service")
            staff_id = request.form.get("staff_id") or None
            comment = request.form.get("comment", "").strip()

            try:
                # Both kinds of feedback are 10 questions, each answered 1-5 stars
                question_set = (services.STAFF_QUESTIONS if feedback_type == "staff"
                                else services.SERVICE_QUESTIONS)
                answers = {}
                for q in question_set:
                    value = request.form.get(f"q{q['no']}", "")
                    if not value.isdigit() or not (1 <= int(value) <= 5):
                        raise ValueError("Please rate all 10 questions with 1 to 5 stars.")
                    answers[q["no"]] = int(value)

                if feedback_type == "staff":
                    Feedback.create(conn, session["user_id"], "staff", None, comment,
                                    staff_id=staff_id, answers=answers)
                else:
                    Feedback.create(conn, session["user_id"], "service", None, comment,
                                    answers=answers)
                flash("Thanks for the feedback.", "success")
            except (ValueError, TypeError) as e:
                flash(str(e) or "Please rate all 10 questions.", "error")
            return redirect(url_for("routes.feedback"))

        staff_members = User.all_staff(conn)
        my_feedback = Feedback.for_customer(conn, session["user_id"])
        return render_template("feedback.html", staff_members=staff_members,
                               my_feedback=my_feedback,
                               staff_questions=services.STAFF_QUESTIONS,
                               service_questions=services.SERVICE_QUESTIONS)
    finally:
        conn.close()


# ======================================================================
# Admin
# ======================================================================

@bp.route("/admin")
@role_required("admin")
def admin_dashboard():
    conn = db()
    try:
        users = User.all(conn)
        flagged = Transaction.flagged(conn, min_score=40)
        high_risk_accounts = {}
        for tx in flagged:
            high_risk_accounts[tx["sender_account"]] = high_risk_accounts.get(
                tx["sender_account"], 0) + 1

        return render_template(
            "admin_dashboard.html", users=users, flagged=flagged,
            high_risk_accounts=high_risk_accounts, as_currency=as_currency,
        )
    finally:
        conn.close()


@bp.route("/admin/staff", methods=["POST"])
@role_required("admin")
def admin_create_staff():
    conn = db()
    try:
        admin_user = User.find_by_id(conn, session["user_id"])
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("All fields are required to create a Staff account.", "error")
            return redirect(url_for("routes.admin_dashboard"))
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("routes.admin_dashboard"))

        try:
            Staff.create_by_admin(conn, admin_user, name, email, password)
            flash(f"Staff account created for {name}.", "success")
        except (ValueError, PermissionError) as e:
            flash(str(e), "error")
        return redirect(url_for("routes.admin_dashboard"))
    finally:
        conn.close()


@bp.route("/admin/performance")
@role_required("admin")
def admin_performance():
    conn = db()
    try:
        performance = services.calculate_staff_performance(conn)
        rated = [p["avg_rating"] for p in performance if p["avg_rating"] is not None]
        overview = {
            "staff_count": len(performance),
            "total_resolved": sum(p["resolved_count"] for p in performance),
            "avg_rating": round(sum(rated) / len(rated), 2) if rated else None,
            "top": performance[0] if performance and (performance[0]["resolved_count"]
                                                      or performance[0]["avg_rating"]) else None,
        }
        return render_template("admin_performance.html", performance=performance,
                               tier_groups=services.group_by_tier(performance),
                               overview=overview, humanize_minutes=humanize_minutes)
    finally:
        conn.close()


@bp.route("/admin/staff/<int:staff_id>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_staff(staff_id):
    """Only the Admin can delete Staff accounts (and only Staff accounts)."""
    conn = db()
    try:
        admin_user = User.find_by_id(conn, session["user_id"])
        target = User.find_by_id(conn, staff_id)
        if not target or target.role != "staff" or not target.is_active:
            flash("No such staff member.", "error")
            return redirect(url_for("routes.admin_performance"))
        if not admin_user.can_delete_staff():
            flash("Only the Admin can delete Staff accounts.", "error")
            return redirect(url_for("routes.admin_performance"))
        if request.form.get("confirm", "").strip() != "DELETE":
            flash("Type DELETE to confirm.", "error")
            return redirect(url_for("routes.admin_staff_detail", staff_id=staff_id))

        User.close_account(conn, target.id, admin_user.id)
        flash(f"Staff account for {target.name} has been deleted.", "success")
        return redirect(url_for("routes.admin_performance"))
    finally:
        conn.close()


@bp.route("/admin/staff/<int:staff_id>")
@role_required("admin")
def admin_staff_detail(staff_id):
    conn = db()
    try:
        detail = services.get_staff_detail(conn, staff_id)
        if detail is None or not detail["staff"].is_active:
            flash("No such staff member.", "error")
            return redirect(url_for("routes.admin_performance"))
        return render_template("admin_staff_detail.html", d=detail,
                               as_currency=as_currency,
                               humanize_minutes=humanize_minutes)
    finally:
        conn.close()


@bp.route("/admin/feedback")
@role_required("admin")
def admin_feedback():
    conn = db()
    try:
        min_rating = request.args.get("min_rating") or None
        feedback_type = request.args.get("type") or None
        start_date = request.args.get("start_date") or None
        end_date = request.args.get("end_date") or None

        feedback_list = services.get_global_feedback(
            conn, min_rating=min_rating, feedback_type=feedback_type,
            start_date=start_date, end_date=end_date,
        )
        service = services.get_service_performance(conn)
        return render_template(
            "admin_feedback.html", feedback_list=feedback_list,
            min_rating=min_rating, feedback_type=feedback_type,
            start_date=start_date, end_date=end_date, service=service,
        )
    finally:
        conn.close()


# ======================================================================
# Staff
# ======================================================================

@bp.route("/staff/dashboard")
@role_required("staff", "admin")
def staff_dashboard():
    conn = db()
    try:
        flagged = Transaction.flagged(conn, min_score=40)
        high_risk_accounts = {}
        for tx in flagged:
            high_risk_accounts[tx["sender_account"]] = high_risk_accounts.get(
                tx["sender_account"], 0) + 1

        accounts = Account.all_with_owner(conn)

        my_feedback = []
        if session.get("role") == "staff":
            my_feedback = services.get_feedback_by_staff(conn, session["user_id"])

        method = request.args.get("method") or None
        recent_transfers = Transaction.recent_all(conn, method=method, limit=25)
        breakdowns = Transaction.risk_breakdowns(
            conn, [t["id"] for t in flagged] + [t["id"] for t in recent_transfers])

        return render_template(
            "staff_dashboard.html", flagged=flagged, high_risk_accounts=high_risk_accounts,
            accounts=accounts, my_feedback=my_feedback, as_currency=as_currency,
            recent_transfers=recent_transfers, method=method, breakdowns=breakdowns,
            login_heatmap=(services.get_login_activity(conn, session["user_id"])
                           if session.get("role") == "staff" else None),
        )
    finally:
        conn.close()


@bp.route("/staff/customer", methods=["POST"])
@role_required("staff")
def staff_create_customer():
    """Only Staff can open Customer accounts on a customer's behalf."""
    conn = db()
    try:
        staff_user = User.find_by_id(conn, session["user_id"])
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        if not name or not email or not phone or not password:
            flash("All fields are required to create a Customer account.", "error")
            return redirect(url_for("routes.staff_dashboard"))
        if not normalize_phone(phone):
            flash("Enter a valid 10-digit mobile number.", "error")
            return redirect(url_for("routes.staff_dashboard"))
        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("routes.staff_dashboard"))

        try:
            user = Customer.create_by_staff(conn, staff_user, name, email, password, phone)
            flash(f"Customer account created for {name}. UPI IDs: {user.upi_id} and {user.upi_email}", "success")
        except (ValueError, PermissionError) as e:
            flash(str(e), "error")
        return redirect(url_for("routes.staff_dashboard"))
    finally:
        conn.close()


@bp.route("/staff/customer/<int:user_id>/delete", methods=["POST"])
@role_required("staff")
def staff_delete_customer(user_id):
    """Only Staff can delete Customer accounts (and only Customer accounts)."""
    conn = db()
    try:
        staff_user = User.find_by_id(conn, session["user_id"])
        target = User.find_by_id(conn, user_id)
        if not target or target.role != "customer" or not target.is_active:
            flash("No such customer.", "error")
            return redirect(url_for("routes.staff_dashboard"))
        if not staff_user.can_delete_customer():
            flash("Only Staff can delete Customer accounts.", "error")
            return redirect(url_for("routes.staff_dashboard"))
        if request.form.get("confirm", "").strip() != "DELETE":
            flash("Type DELETE to confirm.", "error")
            accounts = Account.find_by_user(conn, target.id)
            if accounts:
                return redirect(url_for("routes.staff_account_view", account_id=accounts[0].id))
            return redirect(url_for("routes.staff_dashboard"))

        User.close_account(conn, target.id, staff_user.id)
        flash(f"Customer account for {target.name} has been deleted.", "success")
        return redirect(url_for("routes.staff_dashboard"))
    finally:
        conn.close()


@bp.route("/staff/api/charts")
@role_required("staff", "admin")
def staff_api_charts():
    conn = db()
    try:
        return jsonify(services.bank_wide_chart_data(conn, days=14))
    finally:
        conn.close()


@bp.route("/staff/account/<int:account_id>")
@role_required("staff", "admin")
def staff_account_view(account_id):
    conn = db()
    try:
        account = Account.find_by_id(conn, account_id)
        if not account:
            flash("No such account.", "error")
            return redirect(url_for("routes.staff_dashboard"))
        owner = User.find_by_id(conn, account.user_id)

        start_date = request.args.get("start_date") or None
        end_date = request.args.get("end_date") or None
        risk_level = request.args.get("risk_level") or None

        transactions = services.get_full_transaction_history(
            conn, account.id, start_date, end_date, risk_level
        )

        # Account-holder overview: stats use the FULL history, not the
        # filtered list, so the summary doesn't change when staff filter.
        all_tx = services.get_full_transaction_history(conn, account.id)
        total_sent = Decimal("0.00")
        total_received = Decimal("0.00")
        for tx in all_tx:
            if tx["sender_id"] == account.id:
                total_sent += Decimal(str(tx["amount"]))
            else:
                total_received += Decimal(str(tx["amount"]))
        summary = {
            "total_tx": len(all_tx),
            "total_sent": total_sent,
            "total_received": total_received,
            "flagged": sum(1 for tx in all_tx if tx["status"] in ("warned", "blocked")),
            "max_risk": max((tx["risk_score"] for tx in all_tx), default=0),
            "last_activity": all_tx[0]["timestamp"] if all_tx else None,
        }
        other_accounts = [a for a in Account.find_by_user(conn, owner.id)
                          if a.id != account.id]

        return render_template(
            "staff_account_view.html", account=account, owner=owner,
            transactions=transactions, as_currency=as_currency,
            start_date=start_date, end_date=end_date, risk_level=risk_level,
            summary=summary, other_accounts=other_accounts,
            breakdowns=Transaction.risk_breakdowns(conn, [t["id"] for t in transactions]),
        )
    finally:
        conn.close()


@bp.route("/staff/transaction/<int:tx_id>/resolve", methods=["POST"])
@role_required("staff", "admin")
def staff_resolve_transaction(tx_id):
    conn = db()
    try:
        tx = Transaction.find_by_id(conn, tx_id)
        if not tx:
            flash("Transaction not found.", "error")
            return redirect(url_for("routes.staff_dashboard"))

        Transaction.mark_resolved(conn, tx_id, session["user_id"])
        flash("Transaction marked as reviewed.", "success")
        return redirect(url_for("routes.staff_account_view", account_id=tx.sender_id))
    finally:
        conn.close()