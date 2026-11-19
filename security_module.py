"""
Suspicious Activity Detection & Secure Confirmation module for Ledgerline.

What it does
------------
1. Learns the customer's NORMAL behaviour from past completed transfers
   (average amount, typical daily total, usual hours) and compares the
   current transfer with it.
2. Decides whether the transfer is suspicious and explains WHY in plain
   language (every reason is stored and shown to the customer).
3. Protects a suspicious transfer with step-up authentication:
       Step 1  high-security confirmation password  (within 60 seconds)
       Step 2  one-time password (OTP)
4. Counts every failed attempt (wrong password, password timeout, wrong
   OTP, expired OTP). When failures go above MAX_FAILED_ATTEMPTS the
   transfer is blocked and a detailed alert is raised for staff.
5. Keeps an audit trail of every attempt and notifies the customer.

This file has no Flask code. The pages live in security_routes.py.
It only needs `utils.py` from the existing project.
"""

import json
import secrets
import string
from datetime import datetime, timedelta
from decimal import Decimal
from statistics import median

from utils import hash_password, verify_password, as_currency


# ======================================================================
# Settings — tune these freely
# ======================================================================

PASSWORD_WINDOW_SECONDS = 60      # high-security password must be entered within this time
OTP_VALIDITY_SECONDS = 300        # an OTP stays valid for 5 minutes
MAX_FAILED_ATTEMPTS = 3           # the transfer is blocked when failures go ABOVE this number
                                  # (set to 2 if you want the block on the 3rd failure)

# True  -> a high-risk transfer (score 70+) also gets the password + OTP check
#          instead of being refused outright (only "insufficient balance" is
#          always refused).
# False -> keep the original behaviour: 70+ is blocked immediately.
STEP_UP_FOR_HIGH_RISK = True

# There is no SMS/email gateway in this project, so in demo mode the OTP is
# shown on the page. Set to False once deliver_otp() really sends it.
DEMO_SHOW_OTP = True

# "Sudden big transfer to a brand-new receiver" rule: the customer normally sends
# small amounts (e.g. ~1,000) and suddenly sends a lot more (e.g. 10,000+) to an
# account they have NEVER sent money to before. This ALWAYS asks for password + OTP.
# It fires ONLY the very first time money is sent to that receiver account. From the
# second transfer to the SAME receiver onward, this rule never fires again for that
# receiver, whatever the amount (above or below SPIKE_MIN_AMOUNT) — that receiver is
# now "known". (General checks below, like amount-vs-average, are unrelated to this
# rule and can still apply on their own.)
SPIKE_MIN_AMOUNT = 10000          # only amounts at/above this can count as a spike
SPIKE_MULTIPLE_NEW = 3            # more than 3x the sender's usual single-transfer amount
SPIKE_POINTS = 30

MIN_HISTORY_FOR_PATTERNS = 5      # completed transfers needed before "normal" is trusted
HISTORY_LIMIT = 100               # how many past transfers are used as the baseline
DAILY_MULTIPLE = 2                # today's total above 2x the normal daily total is suspicious
DAILY_TOTAL_POINTS = 25
UNUSUAL_HOUR_POINTS = 10
HIGH_RISK_SCORE = 70
MEDIUM_RISK_SCORE = 40


# ======================================================================
# Database schema (applied automatically by app.py on start-up)
# ======================================================================

SCHEMA_STATEMENTS = [
    # one row per suspicious transfer that needs step-up confirmation
    """
    CREATE TABLE IF NOT EXISTS security_challenges (
        id                INT AUTO_INCREMENT PRIMARY KEY,
        transaction_id    INT NOT NULL UNIQUE,
        user_id           INT NOT NULL,
        status            ENUM('password_pending', 'otp_pending', 'approved', 'blocked', 'cancelled')
                          NOT NULL DEFAULT 'password_pending',
        risk_level        ENUM('LOW', 'MEDIUM', 'HIGH') NOT NULL DEFAULT 'MEDIUM',
        reasons           TEXT NOT NULL,
        failed_attempts   INT NOT NULL DEFAULT 0,
        password_deadline DATETIME NULL,
        otp_hash          VARCHAR(255) NULL,
        otp_expires_at    DATETIME NULL,
        created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        completed_at      DATETIME NULL,
        CONSTRAINT fk_sc_tx   FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
        CONSTRAINT fk_sc_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_sc_user (user_id)
    ) ENGINE=InnoDB
    """,
    # audit trail: every password / OTP attempt and how it ended (no secrets stored)
    """
    CREATE TABLE IF NOT EXISTS secure_confirmation_attempts (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        challenge_id  INT NOT NULL,
        step          ENUM('password', 'otp') NOT NULL,
        outcome       ENUM('success', 'wrong', 'timeout', 'expired') NOT NULL,
        created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_sca_challenge FOREIGN KEY (challenge_id) REFERENCES security_challenges(id) ON DELETE CASCADE,
        INDEX idx_sca_challenge (challenge_id)
    ) ENGINE=InnoDB
    """,
    # the notification that goes to staff when confirmation fails too often
    """
    CREATE TABLE IF NOT EXISTS staff_alerts (
        id                   INT AUTO_INCREMENT PRIMARY KEY,
        challenge_id         INT NOT NULL UNIQUE,
        transaction_id       INT NOT NULL,
        customer_id          INT NOT NULL,
        customer_name        VARCHAR(120) NOT NULL,
        customer_account     VARCHAR(20)  NOT NULL,
        beneficiary_name     VARCHAR(120) NOT NULL,
        beneficiary_account  VARCHAR(20)  NOT NULL,
        amount               DECIMAL(14, 2) NOT NULL,
        risk_level           VARCHAR(10)  NOT NULL,
        failed_attempts      INT NOT NULL,
        explanation          TEXT NOT NULL,
        status               ENUM('open', 'reviewed') NOT NULL DEFAULT 'open',
        reviewed_by          INT NULL,
        reviewed_at          DATETIME NULL,
        created_at           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_sa_challenge FOREIGN KEY (challenge_id) REFERENCES security_challenges(id) ON DELETE CASCADE,
        INDEX idx_sa_status (status)
    ) ENGINE=InnoDB
    """,
    # in-app messages for the customer
    """
    CREATE TABLE IF NOT EXISTS security_notifications (
        id          INT AUTO_INCREMENT PRIMARY KEY,
        user_id     INT NOT NULL,
        title       VARCHAR(120) NOT NULL,
        message     TEXT NOT NULL,
        severity    ENUM('info', 'success', 'warning', 'danger') NOT NULL DEFAULT 'info',
        is_read     TINYINT(1) NOT NULL DEFAULT 0,
        created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_sn_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_sn_user (user_id, is_read)
    ) ENGINE=InnoDB
    """,
]

# (table, column, definition) — picked up by app.py's _ALTER_COLUMNS loop
ALTER_COLUMNS = [
    ("users", "high_security_password", "VARCHAR(255) NULL"),
]


# ======================================================================
# Small helpers
# ======================================================================

def mask_account(number):
    """482913770156 -> XXXXXXXX0156"""
    number = str(number or "")
    return ("X" * max(0, len(number) - 4)) + number[-4:]


def _dec(value):
    return Decimal(str(value))


def seconds_left(deadline):
    if not deadline:
        return 0
    return max(0, int((deadline - datetime.now()).total_seconds()))


def _hour_distance(a, b):
    d = abs(a - b)
    return min(d, 24 - d)


# ======================================================================
# 1. Learn normal behaviour + detect suspicious activity
# ======================================================================

def has_sent_to_before(conn, sender_account_id, receiver_account_id):
    """True once a transfer from this sender account to this exact receiver account
    has ever completed (status allowed/confirmed). Used to tell a brand-new receiver
    from one the sender has already sent money to at least once."""
    cur = conn.cursor()
    cur.execute(
        """SELECT COUNT(*) FROM transactions
           WHERE sender_id = %s AND receiver_id = %s AND status IN ('allowed', 'confirmed')""",
        (sender_account_id, receiver_account_id),
    )
    n = cur.fetchone()[0]
    cur.close()
    return n > 0


def normal_profile(conn, account_id):
    """What this account normally does, from its completed transfers."""
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """SELECT amount, `timestamp` FROM transactions
           WHERE sender_id = %s AND status IN ('allowed', 'confirmed')
           ORDER BY `timestamp` DESC LIMIT %s""",
        (account_id, HISTORY_LIMIT),
    )
    rows = cur.fetchall()
    cur.close()

    amounts = [_dec(r["amount"]) for r in rows]
    daily = {}
    hours = set()
    today_total = Decimal("0")
    today = datetime.now().date()
    for r in rows:
        ts = r["timestamp"]
        daily[ts.date()] = daily.get(ts.date(), Decimal("0")) + _dec(r["amount"])
        hours.add(ts.hour)
        if ts.date() == today:
            today_total += _dec(r["amount"])

    # "normal day" = the middle of the days on which the customer actually sent money
    # (earlier days only, so today's own activity doesn't distort the baseline)
    past_days = [total for day, total in daily.items() if day != today]
    return {
        "count": len(amounts),
        "average": (sum(amounts) / len(amounts)) if amounts else None,
        "median": median(amounts) if amounts else None,   # the usual single-transfer amount
        "max": max(amounts) if amounts else None,
        "typical_daily": median(past_days) if past_days else None,
        "today_total": today_total,
        "hours": hours,
    }


def assess(conn, sender_account, receiver_account, amount, score, factors):
    """Add this module's behaviour checks on top of RiskAnalyzer's result.

    `score` / `factors` come from RiskAnalyzer.analyze(). Returns a dict:
        score    combined score 0-100 (RiskAnalyzer points + this module's points)
        factors  RiskAnalyzer factors + this module's extra factors
        level    'LOW' | 'MEDIUM' | 'HIGH'
        suspicious  True when step-up confirmation is required (combined score 40 or more)
        reasons  plain-language reason for every factor
    """
    amount = _dec(amount)
    factors = list(factors)
    extra_points = 0
    profile = normal_profile(conn, sender_account.id)

    # --- Sudden big transfer, first time ever to this receiver -----------------
    force_step_up = False
    is_first_time_to_this_receiver = not has_sent_to_before(conn, sender_account.id, receiver_account.id)
    if is_first_time_to_this_receiver and amount >= SPIKE_MIN_AMOUNT:
        usual = profile["median"]
        if usual:
            if amount > usual * SPIKE_MULTIPLE_NEW:
                factors.append({
                    "code": "AMOUNT_SPIKE",
                    "title": "Sudden big transfer to a new receiver",
                    "detail": (f"This is the first time you are sending money to this account. You usually "
                               f"send about {as_currency(usual)} per transfer, but this is {as_currency(amount)} "
                               f"({amount / usual:.1f}x your usual amount)."),
                    "points": SPIKE_POINTS,
                })
                extra_points += SPIKE_POINTS
                force_step_up = True
        else:
            factors.append({
                "code": "NO_HISTORY_LARGE",
                "title": "Large transfer with no history",
                "detail": (f"{as_currency(amount)} is a large amount and this account has no completed "
                           f"transfers yet to compare with."),
                "points": SPIKE_POINTS,
            })
            extra_points += SPIKE_POINTS
            force_step_up = True
    # From the second transfer to this SAME receiver onward, nothing above fires again
    # for it, whatever the amount — that receiver is now "known".

    if profile["count"] >= MIN_HISTORY_FOR_PATTERNS:
        # Compare today's total with a normal day
        typical = profile["typical_daily"]
        if typical and typical > 0:
            projected = profile["today_total"] + amount
            if projected > typical * DAILY_MULTIPLE:
                factors.append({
                    "code": "DAILY_TOTAL",
                    "title": "Much higher than a normal day",
                    "detail": (f"With this transfer you would send {as_currency(projected)} today. "
                               f"On a normal day you send about {as_currency(typical)}."),
                    "points": DAILY_TOTAL_POINTS,
                })
                extra_points += DAILY_TOTAL_POINTS

        # Time of day nobody in the history ever used (at least 3 hours away from any usual hour)
        now_hour = datetime.now().hour
        if profile["hours"] and profile["count"] >= 10:
            nearest = min(_hour_distance(now_hour, h) for h in profile["hours"])
            if nearest >= 3:
                factors.append({
                    "code": "UNUSUAL_HOUR",
                    "title": "Unusual time of day",
                    "detail": f"You do not normally send money around {now_hour:02d}:00.",
                    "points": UNUSUAL_HOUR_POINTS,
                })
                extra_points += UNUSUAL_HOUR_POINTS

    combined = max(0, min(100, int(score) + extra_points))

    if combined >= HIGH_RISK_SCORE:
        level = "HIGH"
    elif combined >= MEDIUM_RISK_SCORE or force_step_up:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": combined,
        "factors": factors,
        "level": level,
        "suspicious": level != "LOW",
        "reasons": [f["detail"] for f in factors if f.get("points")],
        "profile": profile,
    }


# ======================================================================
# 2. Challenge life-cycle: open -> password -> OTP -> approved / blocked
# ======================================================================

def open_challenge(conn, tx_id, user_id, assessment):
    """Create the challenge for a held (status 'warned') transaction and
    tell the customer what happened and why."""
    deadline = datetime.now() + timedelta(seconds=PASSWORD_WINDOW_SECONDS)
    cur = conn.cursor()
    cur.execute(
        """INSERT INTO security_challenges
               (transaction_id, user_id, status, risk_level, reasons, password_deadline)
           VALUES (%s, %s, 'password_pending', %s, %s, %s)""",
        (tx_id, user_id, assessment["level"], json.dumps(assessment["reasons"]), deadline),
    )
    challenge_id = cur.lastrowid
    conn.commit()
    cur.close()

    p = tx_parties(conn, tx_id)
    why = " ".join(assessment["reasons"]) or "The transfer differs from your normal behaviour."
    notify(
        conn, user_id, "Suspicious activity detected",
        f"Your transfer of {as_currency(p['amount'])} to {p['receiver_name']} "
        f"(account {mask_account(p['receiver_account'])}) looks suspicious. Why: {why} "
        f"Status: on hold, no money has moved. What to do: enter your high-security "
        f"password within {PASSWORD_WINDOW_SECONDS} seconds, then the OTP we send you.",
        "warning",
    )
    return challenge_id


def get_challenge(conn, tx_id, user_id, lock=False):
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT * FROM security_challenges WHERE transaction_id = %s AND user_id = %s"
        + (" FOR UPDATE" if lock else ""),
        (tx_id, user_id),
    )
    ch = cur.fetchone()
    cur.close()
    return ch


def get_reasons(ch):
    try:
        return json.loads(ch["reasons"])
    except (TypeError, ValueError):
        return []


def log_attempt(conn, challenge_id, step, outcome):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO secure_confirmation_attempts (challenge_id, step, outcome) VALUES (%s, %s, %s)",
        (challenge_id, step, outcome),
    )
    conn.commit()
    cur.close()


def register_failure(conn, ch, step, outcome):
    """Count one failed attempt. Returns True if this failure blocked the transfer.
    Failures are: password timeout, wrong password, OTP expired, wrong OTP."""
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO secure_confirmation_attempts (challenge_id, step, outcome) VALUES (%s, %s, %s)",
        (ch["id"], step, outcome),
    )
    ch["failed_attempts"] += 1

    if ch["failed_attempts"] > MAX_FAILED_ATTEMPTS:
        cur.execute(
            """UPDATE security_challenges
               SET failed_attempts = %s, status = 'blocked', password_deadline = NULL,
                   otp_hash = NULL, otp_expires_at = NULL, completed_at = NOW()
               WHERE id = %s""",
            (ch["failed_attempts"], ch["id"]),
        )
        cur.execute("UPDATE transactions SET status = 'blocked' WHERE id = %s",
                    (ch["transaction_id"],))
        conn.commit()
        cur.close()
        ch["status"] = "blocked"
        _escalate_to_staff(conn, ch)
        return True

    if step == "password":
        # a fresh 60-second window for the next try
        ch["password_deadline"] = datetime.now() + timedelta(seconds=PASSWORD_WINDOW_SECONDS)
    cur.execute(
        "UPDATE security_challenges SET failed_attempts = %s, password_deadline = %s WHERE id = %s",
        (ch["failed_attempts"], ch["password_deadline"], ch["id"]),
    )
    conn.commit()
    cur.close()
    return False


def enforce_timeouts(conn, ch):
    """Apply the 60-second password rule and the OTP validity rule.
    Returns 'password_timeout', 'otp_expired' or None."""
    now = datetime.now()
    if (ch["status"] == "password_pending" and ch["password_deadline"]
            and now > ch["password_deadline"]):
        register_failure(conn, ch, "password", "timeout")
        return "password_timeout"

    if (ch["status"] == "otp_pending" and ch["otp_hash"] and ch["otp_expires_at"]
            and now > ch["otp_expires_at"]):
        cur = conn.cursor()
        cur.execute(
            "UPDATE security_challenges SET otp_hash = NULL, otp_expires_at = NULL WHERE id = %s",
            (ch["id"],))
        conn.commit()
        cur.close()
        ch["otp_hash"] = None
        ch["otp_expires_at"] = None
        register_failure(conn, ch, "otp", "expired")
        return "otp_expired"
    return None


# ---- Step 1: high-security password -----------------------------------

def has_high_security_password(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT high_security_password FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    return bool(row and row[0])


def verify_high_security_password(conn, user_id, plaintext):
    cur = conn.cursor()
    cur.execute("SELECT high_security_password FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    cur.close()
    return bool(row and row[0] and verify_password(plaintext, row[0]))


def set_high_security_password(conn, user_id, plaintext):
    cur = conn.cursor()
    cur.execute("UPDATE users SET high_security_password = %s WHERE id = %s",
                (hash_password(plaintext), user_id))
    conn.commit()
    cur.close()


def validate_high_security_password(plaintext):
    """Returns an error message, or None if the password is strong enough."""
    if len(plaintext) < 8:
        return "The high-security password must be at least 8 characters long."
    if not any(c.isalpha() for c in plaintext):
        return "The high-security password must contain a letter."
    if not any(c.isdigit() for c in plaintext):
        return "The high-security password must contain a digit."
    if not any(c in string.punctuation for c in plaintext):
        return "The high-security password must contain a symbol such as @ # $ !"
    return None


# ---- Step 2: OTP ---------------------------------------------------------

def deliver_otp(user_id, otp):
    """PLUG-IN POINT: send `otp` to the customer's registered mobile number or
    email here (SMS gateway, SMTP, ...). The OTP is never written to the
    database in plain text or to any log."""
    return True


def issue_otp(conn, ch):
    """Generate an OTP, store only its hash, deliver it. Returns the plain OTP
    (the route shows it only while DEMO_SHOW_OTP is True)."""
    otp = "".join(secrets.choice(string.digits) for _ in range(6))
    expires = datetime.now() + timedelta(seconds=OTP_VALIDITY_SECONDS)
    cur = conn.cursor()
    cur.execute(
        """UPDATE security_challenges
           SET status = 'otp_pending', password_deadline = NULL, otp_hash = %s, otp_expires_at = %s
           WHERE id = %s""",
        (hash_password(otp), expires, ch["id"]),
    )
    conn.commit()
    cur.close()
    ch["status"] = "otp_pending"
    ch["password_deadline"] = None
    ch["otp_expires_at"] = expires
    ch["otp_hash"] = "set"
    deliver_otp(ch["user_id"], otp)
    return otp


def verify_otp(conn, ch, otp):
    cur = conn.cursor()
    cur.execute("SELECT otp_hash FROM security_challenges WHERE id = %s", (ch["id"],))
    row = cur.fetchone()
    cur.close()
    return bool(row and row[0] and verify_password(otp, row[0]))


# ---- finishing ---------------------------------------------------------

def claim_approval(conn, ch):
    """Atomically move otp_pending -> approved. Returns False if somebody else
    (a double click, a second tab) already did, so money can never move twice."""
    cur = conn.cursor()
    cur.execute(
        """UPDATE security_challenges SET status = 'approved', otp_hash = NULL,
               otp_expires_at = NULL, completed_at = NOW()
           WHERE id = %s AND status = 'otp_pending'""",
        (ch["id"],),
    )
    claimed = cur.rowcount == 1
    conn.commit()
    cur.close()
    return claimed


def finish_failed_transfer(conn, ch):
    """The transfer could not be completed after approval (e.g. balance dropped)."""
    cur = conn.cursor()
    cur.execute("UPDATE security_challenges SET status = 'cancelled' WHERE id = %s", (ch["id"],))
    cur.execute("UPDATE transactions SET status = 'blocked' WHERE id = %s", (ch["transaction_id"],))
    conn.commit()
    cur.close()


def mark_transfer_confirmed(conn, ch):
    cur = conn.cursor()
    cur.execute("UPDATE transactions SET status = 'confirmed' WHERE id = %s", (ch["transaction_id"],))
    conn.commit()
    cur.close()
    p = tx_parties(conn, ch["transaction_id"])
    notify(conn, ch["user_id"], "Transfer completed",
           f"Secure confirmation passed. {as_currency(p['amount'])} was sent to "
           f"{p['receiver_name']} (account {mask_account(p['receiver_account'])}).", "success")


def cancel_challenge(conn, ch):
    cur = conn.cursor()
    cur.execute(
        """UPDATE security_challenges SET status = 'cancelled', password_deadline = NULL,
               otp_hash = NULL, otp_expires_at = NULL, completed_at = NOW()
           WHERE id = %s AND status IN ('password_pending', 'otp_pending')""",
        (ch["id"],),
    )
    changed = cur.rowcount == 1
    if changed:
        cur.execute("UPDATE transactions SET status = 'blocked' WHERE id = %s", (ch["transaction_id"],))
    conn.commit()
    cur.close()
    if changed:
        p = tx_parties(conn, ch["transaction_id"])
        notify(conn, ch["user_id"], "Transfer cancelled",
               f"You cancelled the held transfer of {as_currency(p['amount'])} to {p['receiver_name']}. "
               f"No money was sent.", "info")
    return changed


# ======================================================================
# 3. Staff escalation + customer notifications
# ======================================================================

def tx_parties(conn, tx_id):
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """SELECT t.id, t.amount, t.`timestamp` AS ts,
                  sa.account_number AS sender_account, su.id AS sender_user_id, su.name AS sender_name,
                  ra.account_number AS receiver_account, ru.name AS receiver_name
           FROM transactions t
           JOIN accounts sa ON sa.id = t.sender_id   JOIN users su ON su.id = sa.user_id
           JOIN accounts ra ON ra.id = t.receiver_id JOIN users ru ON ru.id = ra.user_id
           WHERE t.id = %s""",
        (tx_id,),
    )
    row = cur.fetchone()
    cur.close()
    return row


_OUTCOME_TEXT = {
    ("password", "wrong"): "wrong high-security password",
    ("password", "timeout"): "high-security password not entered within 1 minute",
    ("otp", "wrong"): "wrong OTP",
    ("otp", "expired"): "OTP expired",
}


def _failure_breakdown(conn, challenge_id):
    cur = conn.cursor()
    cur.execute(
        """SELECT step, outcome, COUNT(*) FROM secure_confirmation_attempts
           WHERE challenge_id = %s AND outcome <> 'success' GROUP BY step, outcome""",
        (challenge_id,),
    )
    rows = cur.fetchall()
    cur.close()
    parts = []
    for step, outcome, n in rows:
        parts.append(f"{_OUTCOME_TEXT.get((step, outcome), outcome)} x{n}")
    return parts


def _escalate_to_staff(conn, ch):
    p = tx_parties(conn, ch["transaction_id"])
    reasons = get_reasons(ch)
    failures = _failure_breakdown(conn, ch["id"])

    explanation = (
        f"{p['sender_name']} tried to transfer {as_currency(p['amount'])} to "
        f"{p['receiver_name']} (account {p['receiver_account']}). "
        f"Why it was flagged: {' '.join(reasons) or 'it differs from the normal pattern.'} "
        f"Secure confirmation failed {ch['failed_attempts']} times "
        f"({', '.join(failures) or 'no detail'}). "
        f"The transfer was blocked automatically and needs staff review."
    )

    cur = conn.cursor()
    cur.execute(
        """INSERT IGNORE INTO staff_alerts
               (challenge_id, transaction_id, customer_id, customer_name, customer_account,
                beneficiary_name, beneficiary_account, amount, risk_level, failed_attempts, explanation)
           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
        (ch["id"], ch["transaction_id"], p["sender_user_id"], p["sender_name"], p["sender_account"],
         p["receiver_name"], p["receiver_account"], p["amount"], ch["risk_level"],
         ch["failed_attempts"], explanation),
    )
    conn.commit()
    cur.close()

    notify(
        conn, ch["user_id"], "Transfer blocked for your safety",
        f"Your transfer of {as_currency(p['amount'])} to {p['receiver_name']} "
        f"(account {mask_account(p['receiver_account'])}) was blocked because secure confirmation "
        f"failed too many times. No money was sent. Bank staff have been notified. "
        f"If this was you, please contact the bank.",
        "danger",
    )


def list_alerts(conn, only_open=False):
    cur = conn.cursor(dictionary=True)
    cur.execute(
        """SELECT a.*, u.name AS reviewed_by_name
           FROM staff_alerts a LEFT JOIN users u ON u.id = a.reviewed_by
           """ + ("WHERE a.status = 'open' " if only_open else "") +
        "ORDER BY a.created_at DESC LIMIT 200"
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def open_alert_count(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM staff_alerts WHERE status = 'open'")
    n = cur.fetchone()[0]
    cur.close()
    return n


def mark_alert_reviewed(conn, alert_id, staff_id):
    cur = conn.cursor()
    cur.execute(
        """UPDATE staff_alerts SET status = 'reviewed', reviewed_by = %s, reviewed_at = NOW()
           WHERE id = %s AND status = 'open'""",
        (staff_id, alert_id),
    )
    changed = cur.rowcount == 1
    conn.commit()
    cur.close()
    return changed


def notify(conn, user_id, title, message, severity="info"):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO security_notifications (user_id, title, message, severity) VALUES (%s, %s, %s, %s)",
        (user_id, title, message, severity),
    )
    conn.commit()
    cur.close()


def list_notifications(conn, user_id, limit=50):
    cur = conn.cursor(dictionary=True)
    cur.execute(
        "SELECT * FROM security_notifications WHERE user_id = %s ORDER BY created_at DESC, id DESC LIMIT %s",
        (user_id, limit),
    )
    rows = cur.fetchall()
    cur.close()
    return rows


def unread_count(conn, user_id):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM security_notifications WHERE user_id = %s AND is_read = 0",
                (user_id,))
    n = cur.fetchone()[0]
    cur.close()
    return n


def mark_all_read(conn, user_id):
    cur = conn.cursor()
    cur.execute("UPDATE security_notifications SET is_read = 1 WHERE user_id = %s AND is_read = 0",
                (user_id,))
    conn.commit()
    cur.close()