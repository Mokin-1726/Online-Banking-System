"""
Domain models for Ledgerline.

Design notes (OOAD):
  User (abstract-ish base)
    ├── Admin      — singleton, manages Staff accounts, sees the whole bank
    ├── Staff      — created only by Admin
    └── Customer   — self-registers, owns Accounts

  Account      — one bank account, always owned by exactly one User
  Transaction  — one transfer attempt between two Accounts
  RiskAnalyzer — stateless-per-call service object that scores a
                 prospective Transaction before it is committed

Every class here is a thin wrapper around plain SQL executed through
the mysql.connector connection handed to it — there is no ORM, so the
classes exist to keep the *rules* (who can do what, how risk is scored)
in one place rather than scattered across routes.
"""

from datetime import datetime, timedelta
from decimal import Decimal

from utils import (hash_password, verify_password, generate_account_number,
                   normalize_phone, make_upi_id, make_email_upi_id, as_currency)


# ======================================================================
# User hierarchy
# ======================================================================

class User:
    """Base class for every account holder."""

    ROLE = "customer"  # overridden by subclasses; matches the DB enum

    def __init__(self, id=None, name=None, email=None, password_hash=None,
                 role=None, created_at=None, is_active=True, phone=None, upi_id=None, upi_email=None):
        self.phone = phone
        self.upi_id = upi_id
        self.upi_email = upi_email
        self.id = id
        self.name = name
        self.email = email
        self.password_hash = password_hash
        self.role = role or self.ROLE
        self.created_at = created_at
        self.is_active = is_active

    # -- factory ---------------------------------------------------
    @staticmethod
    def from_row(row):
        """Build the correct subclass instance from a `users` table row."""
        if row is None:
            return None
        role = row["role"]
        cls = {"admin": Admin, "staff": Staff, "customer": Customer}.get(role, User)
        return cls(
            id=row["id"],
            name=row["name"],
            email=row["email"],
            password_hash=row["password"],
            role=role,
            created_at=row.get("created_at"),
            is_active=bool(row.get("is_active", 1)),
            phone=row.get("phone"),
            upi_id=row.get("upi_id"),
            upi_email=row.get("upi_email"),
        )

    # -- lookups -----------------------------------------------------
    @staticmethod
    def find_by_email(conn, email):
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        cur.close()
        return User.from_row(row)

    @staticmethod
    def find_by_phone(conn, phone):
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE phone = %s", (phone,))
        row = cur.fetchone()
        cur.close()
        return User.from_row(row)

    @staticmethod
    def find_by_upi(conn, upi_id):
        cur = conn.cursor(dictionary=True)
        # a customer has two UPI IDs (from phone, from email); either one works
        cur.execute("SELECT * FROM users WHERE upi_id = %s OR upi_email = %s", (upi_id, upi_id))
        row = cur.fetchone()
        cur.close()
        return User.from_row(row)

    @staticmethod
    def email_upi_for(conn, email, user_id=None):
        """Email-based UPI ID, made unique (abc@ledgerline, or abc2@ledgerline if taken)."""
        n = 1
        while True:
            candidate = make_email_upi_id(email, "" if n == 1 else str(n))
            other = User.find_by_upi(conn, candidate)
            if not other or other.id == user_id:
                return candidate
            n += 1

    @staticmethod
    def update_profile(conn, user_id, name, email, phone_raw):
        """Edit a customer's own details. The UPI ID is (re)created from the
        phone number, so changing the phone number changes the UPI ID.
        Raises ValueError with a user-friendly message."""
        current = User.find_by_id(conn, user_id)
        if not name or not email:
            raise ValueError("Name and email are required.")

        other = User.find_by_email(conn, email)
        if other and other.id != user_id:
            raise ValueError("Another account already uses this email.")

        phone = upi_id = None
        if phone_raw:
            phone = normalize_phone(phone_raw)
            if not phone:
                raise ValueError("Enter a valid 10-digit mobile number.")
            other = User.find_by_phone(conn, phone)
            if other and other.id != user_id:
                raise ValueError("This phone number is already registered with another account.")
            upi_id = make_upi_id(phone)
            clash = User.find_by_upi(conn, upi_id)
            if clash and clash.id != user_id:
                raise ValueError("This phone number's UPI ID is already taken.")
        elif current and current.phone:
            raise ValueError("Phone number can't be removed — enter a valid 10-digit number.")

        upi_email = User.email_upi_for(conn, email, user_id)
        cur = conn.cursor()
        cur.execute(
            """UPDATE users SET name = %s, email = %s, phone = %s, upi_id = %s, upi_email = %s
               WHERE id = %s""",
            (name, email, phone, upi_id, upi_email, user_id),
        )
        conn.commit()
        cur.close()
        return User.find_by_id(conn, user_id)

    @staticmethod
    def find_by_id(conn, user_id):
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cur.fetchone()
        cur.close()
        return User.from_row(row)

    @staticmethod
    def all(conn):
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users ORDER BY created_at DESC")
        rows = cur.fetchall()
        cur.close()
        return [User.from_row(r) for r in rows]

    @staticmethod
    def all_staff(conn):
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE role = 'staff' AND is_active = 1 ORDER BY name ASC")
        rows = cur.fetchall()
        cur.close()
        return [User.from_row(r) for r in rows]

    @staticmethod
    def record_login(conn, user_id):
        """One row per successful login — the data behind the green login calendar."""
        from datetime import datetime
        cur = conn.cursor()
        cur.execute("INSERT INTO login_events (user_id, logged_in_at) VALUES (%s, %s)",
                    (user_id, datetime.now()))
        conn.commit()
        cur.close()

    @staticmethod
    def login_counts(conn, user_id, since):
        """{date: number of logins that day} from `since` (a date) until now."""
        cur = conn.cursor()
        cur.execute(
            """SELECT DATE(logged_in_at), COUNT(*) FROM login_events
               WHERE user_id = %s AND logged_in_at >= %s
               GROUP BY DATE(logged_in_at)""",
            (user_id, since),
        )
        rows = cur.fetchall()
        cur.close()
        return {d: int(n) for d, n in rows}

    @staticmethod
    def close_account(conn, user_id, closed_by_id):
        """Delete = close the account: the person can no longer log in, and
        disappears from lists, rankings and transfers. Their records
        (transactions, ratings, risk logs) are kept so other people's
        history and the audit trail stay intact."""
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET is_active = 0, deleted_at = NOW(), deleted_by = %s WHERE id = %s",
            (closed_by_id, user_id),
        )
        conn.commit()
        cur.close()

    @staticmethod
    def admin_exists(conn):
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
        count = cur.fetchone()[0]
        cur.close()
        return count > 0

    @staticmethod
    def update_password(conn, user_id, new_password_hash):
        cur = conn.cursor()
        cur.execute("UPDATE users SET password = %s WHERE id = %s", (new_password_hash, user_id))
        conn.commit()
        cur.close()

    # -- auth ----------------------------------------------------------
    def check_password(self, plaintext):
        return verify_password(plaintext, self.password_hash)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "email": self.email,
            "role": self.role,
            "created_at": str(self.created_at) if self.created_at else None,
            "is_active": self.is_active,
        }

    # -- permissions (overridden per subclass) --------------------------
    def can_create_staff(self):
        return False

    def can_create_customer(self):
        return False

    def can_delete_staff(self):
        return False

    def can_delete_customer(self):
        return False

    def can_view_all_users(self):
        return False

    def can_view_flagged_transactions(self):
        return False


class Customer(User):
    ROLE = "customer"

    @staticmethod
    def _insert_customer(conn, name, email, plaintext_password, phone_raw):
        """Shared by self-registration and staff-provisioning. The UPI ID is
        generated from the phone number."""
        if User.find_by_email(conn, email):
            raise ValueError("An account with this email already exists.")

        phone = upi_id = None
        if phone_raw:
            phone = normalize_phone(phone_raw)
            if not phone:
                raise ValueError("Enter a valid 10-digit mobile number.")
            if User.find_by_phone(conn, phone):
                raise ValueError("This phone number is already registered.")
            upi_id = make_upi_id(phone)
            if User.find_by_upi(conn, upi_id):
                raise ValueError("This phone number's UPI ID is already taken.")

        upi_email = User.email_upi_for(conn, email)
        password_hash = hash_password(plaintext_password)
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO users (name, email, password, role, phone, upi_id, upi_email)
               VALUES (%s, %s, %s, 'customer', %s, %s, %s)""",
            (name, email, password_hash, phone, upi_id, upi_email),
        )
        user_id = cur.lastrowid
        conn.commit()
        cur.close()

        # Every new customer gets one account opened automatically.
        Account.create(conn, user_id)
        return User.find_by_id(conn, user_id)

    @staticmethod
    def register(conn, name, email, plaintext_password, phone=None):
        """Self-registration. Raises ValueError on duplicate email / phone."""
        return Customer._insert_customer(conn, name, email, plaintext_password, phone)

    @staticmethod
    def create_by_staff(conn, staff_user, name, email, plaintext_password, phone=None):
        """Staff-provisioned customer account — same result as self-registration,
        just initiated from the Staff Dashboard instead of the public /register form."""
        if not staff_user.can_create_customer():
            raise PermissionError("Only Staff can create Customer accounts.")
        return Customer._insert_customer(conn, name, email, plaintext_password, phone)


class Staff(User):
    ROLE = "staff"

    def can_create_customer(self):
        return True

    def can_delete_customer(self):
        return True

    @staticmethod
    def create_by_admin(conn, admin_user, name, email, plaintext_password):
        if not admin_user.can_create_staff():
            raise PermissionError("Only the Admin can create Staff accounts.")
        if User.find_by_email(conn, email):
            raise ValueError("An account with this email already exists.")

        password_hash = hash_password(plaintext_password)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, 'staff')",
            (name, email, password_hash),
        )
        user_id = cur.lastrowid
        conn.commit()
        cur.close()
        return User.find_by_id(conn, user_id)

    def can_view_flagged_transactions(self):
        return True


class Admin(User):
    ROLE = "admin"

    @staticmethod
    def bootstrap(conn, name, email, plaintext_password):
        """Create the single Admin account. Refuses if one already exists
        (singleton admin requirement)."""
        if User.admin_exists(conn):
            raise ValueError("An Admin account already exists; only one is allowed.")

        password_hash = hash_password(plaintext_password)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, 'admin')",
            (name, email, password_hash),
        )
        user_id = cur.lastrowid
        conn.commit()
        cur.close()
        return User.find_by_id(conn, user_id)

    def can_create_staff(self):
        return True

    def can_delete_staff(self):
        return True

    def can_view_all_users(self):
        return True

    def can_view_flagged_transactions(self):
        return True


# ======================================================================
# Account
# ======================================================================

class Account:
    def __init__(self, id=None, user_id=None, account_number=None,
                 balance=Decimal("0.00"), created_at=None):
        self.id = id
        self.user_id = user_id
        self.account_number = account_number
        self.balance = balance
        self.created_at = created_at

    @staticmethod
    def from_row(row):
        if row is None:
            return None
        return Account(
            id=row["id"],
            user_id=row["user_id"],
            account_number=row["account_number"],
            balance=row["balance"],
            created_at=row.get("created_at"),
        )

    @staticmethod
    def create(conn, user_id, opening_balance=Decimal("0.00")):
        account_number = generate_account_number()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO accounts (user_id, account_number, balance) VALUES (%s, %s, %s)",
            (user_id, account_number, opening_balance),
        )
        account_id = cur.lastrowid
        conn.commit()
        cur.close()
        return Account.find_by_id(conn, account_id)

    @staticmethod
    def find_by_id(conn, account_id):
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM accounts WHERE id = %s", (account_id,))
        row = cur.fetchone()
        cur.close()
        return Account.from_row(row)

    @staticmethod
    def find_by_user(conn, user_id):
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM accounts WHERE user_id = %s", (user_id,))
        rows = cur.fetchall()
        cur.close()
        return [Account.from_row(r) for r in rows]

    @staticmethod
    def find_by_account_number(conn, account_number):
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM accounts WHERE account_number = %s", (account_number,))
        row = cur.fetchone()
        cur.close()
        return Account.from_row(row)

    @staticmethod
    def all_with_owner(conn):
        cur = conn.cursor(dictionary=True)
        cur.execute("""
            SELECT accounts.*, users.name AS owner_name, users.email AS owner_email,
                   users.role AS owner_role, users.phone AS owner_phone,
                   users.upi_id AS owner_upi, users.upi_email AS owner_upi_email
            FROM accounts
            JOIN users ON users.id = accounts.user_id
            WHERE users.is_active = 1
            ORDER BY accounts.id
        """)
        rows = cur.fetchall()
        cur.close()
        return rows

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "account_number": self.account_number,
            "balance": str(self.balance),
            "created_at": str(self.created_at) if self.created_at else None,
        }


# ======================================================================
# Transaction
# ======================================================================

class Transaction:
    def __init__(self, id=None, sender_id=None, receiver_id=None, amount=None,
                 timestamp=None, risk_score=0, status="allowed",
                 transfer_method="account", receiver_ref=None):
        self.transfer_method = transfer_method
        self.receiver_ref = receiver_ref
        self.id = id
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.amount = amount
        self.timestamp = timestamp
        self.risk_score = risk_score
        self.status = status

    @staticmethod
    def from_row(row):
        if row is None:
            return None
        return Transaction(
            id=row["id"],
            sender_id=row["sender_id"],
            receiver_id=row["receiver_id"],
            amount=row["amount"],
            timestamp=row.get("timestamp"),
            risk_score=row.get("risk_score", 0),
            status=row.get("status", "allowed"),
            transfer_method=row.get("transfer_method") or "account",
            receiver_ref=row.get("receiver_ref"),
        )

    @staticmethod
    def create(conn, sender_id, receiver_id, amount, risk_score, status,
               transfer_method="account", receiver_ref=None):
        """transfer_method is how the sender addressed the receiver
        ('account' | 'upi' | 'phone'); receiver_ref is the exact account
        number / UPI ID / phone number they typed."""
        cur = conn.cursor()
        cur.execute(
            """INSERT INTO transactions
                   (sender_id, receiver_id, amount, risk_score, status, transfer_method, receiver_ref)
               VALUES (%s, %s, %s, %s, %s, %s, %s)""",
            (sender_id, receiver_id, amount, risk_score, status, transfer_method, receiver_ref),
        )
        tx_id = cur.lastrowid
        conn.commit()
        cur.close()
        return Transaction.find_by_id(conn, tx_id)

    @staticmethod
    def risk_breakdowns(conn, tx_ids):
        """{transaction_id: [factor dicts]} from risk_logs — why each transaction
        got its risk score. Older rows (before points were stored) have points=None."""
        tx_ids = [int(i) for i in tx_ids if i is not None]
        if not tx_ids:
            return {}
        placeholders = ",".join(["%s"] * len(tx_ids))
        cur = conn.cursor(dictionary=True)
        cur.execute(
            f"""SELECT transaction_id, rule_code, title, reason, points, score
                FROM risk_logs WHERE transaction_id IN ({placeholders}) ORDER BY id""",
            tuple(tx_ids),
        )
        rows = cur.fetchall()
        cur.close()
        result = {}
        for r in rows:
            result.setdefault(r["transaction_id"], []).append({
                "code": r["rule_code"] or "",
                "title": r["title"] or "Risk signal",
                "detail": r["reason"],
                "points": r["points"],
            })
        return result

    @staticmethod
    def recent_all(conn, method=None, limit=25):
        """Latest transfers bank-wide (Staff dashboard), optionally only
        those sent via one method: 'account', 'upi' or 'phone'."""
        query = """
            SELECT t.*, sa.account_number AS sender_account, ra.account_number AS receiver_account,
                   su.name AS sender_name, ru.name AS receiver_name
            FROM transactions t
            JOIN accounts sa ON sa.id = t.sender_id
            JOIN accounts ra ON ra.id = t.receiver_id
            JOIN users su ON su.id = sa.user_id
            JOIN users ru ON ru.id = ra.user_id
        """
        params = []
        if method in ("account", "upi", "phone"):
            query += " WHERE t.transfer_method = %s"
            params.append(method)
        query += " ORDER BY t.timestamp DESC LIMIT %s"
        params.append(limit)
        cur = conn.cursor(dictionary=True)
        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def find_by_id(conn, tx_id):
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM transactions WHERE id = %s", (tx_id,))
        row = cur.fetchone()
        cur.close()
        return Transaction.from_row(row)

    @staticmethod
    def for_account(conn, account_id, start_date=None, end_date=None):
        """History for one account, optionally filtered by date (inclusive)."""
        query = """
            SELECT t.*, sa.account_number AS sender_account, ra.account_number AS receiver_account
            FROM transactions t
            JOIN accounts sa ON sa.id = t.sender_id
            JOIN accounts ra ON ra.id = t.receiver_id
            WHERE (t.sender_id = %s OR t.receiver_id = %s)
        """
        params = [account_id, account_id]
        if start_date:
            query += " AND t.timestamp >= %s"
            params.append(start_date)
        if end_date:
            query += " AND t.timestamp <= %s"
            params.append(end_date)
        query += " ORDER BY t.timestamp DESC"

        cur = conn.cursor(dictionary=True)
        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def recent_for_account(conn, account_id, within_minutes=60):
        cur = conn.cursor(dictionary=True)
        cutoff = datetime.now() - timedelta(minutes=within_minutes)
        cur.execute(
            """SELECT * FROM transactions
               WHERE sender_id = %s AND `timestamp` >= %s
               ORDER BY `timestamp` DESC""",
            (account_id, cutoff),
        )
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def history_for_sender(conn, account_id, exclude_receiver=None, limit=50):
        """Past outgoing transfers, used by RiskAnalyzer to learn a baseline."""
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """SELECT * FROM transactions
               WHERE sender_id = %s AND status IN ('allowed', 'confirmed')
               ORDER BY `timestamp` DESC LIMIT %s""",
            (account_id, limit),
        )
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def flagged(conn, min_score=40):
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """SELECT t.*, sa.account_number AS sender_account, ra.account_number AS receiver_account,
                      su.name AS sender_name, ru.name AS receiver_name
               FROM transactions t
               JOIN accounts sa ON sa.id = t.sender_id
               JOIN accounts ra ON ra.id = t.receiver_id
               JOIN users su ON su.id = sa.user_id
               JOIN users ru ON ru.id = ra.user_id
               WHERE t.risk_score >= %s
               ORDER BY t.timestamp DESC""",
            (min_score,),
        )
        rows = cur.fetchall()
        cur.close()
        return rows

    #: risk_level buckets used by the Staff account deep-view filter
    RISK_LEVEL_RANGES = {
        "low": (0, 39),
        "medium": (40, 69),
        "high": (70, 100),
    }

    @staticmethod
    def for_account_filtered(conn, account_id, start_date=None, end_date=None, risk_level=None):
        """Full transaction history for one account (both sent and received),
        with optional date range and risk_level ('low'/'medium'/'high') filters.
        Used by the Staff account deep-view page."""
        query = """
            SELECT t.*, sa.account_number AS sender_account, ra.account_number AS receiver_account,
                   ru_staff.name AS resolved_by_name
            FROM transactions t
            JOIN accounts sa ON sa.id = t.sender_id
            JOIN accounts ra ON ra.id = t.receiver_id
            LEFT JOIN users ru_staff ON ru_staff.id = t.resolved_by
            WHERE (t.sender_id = %s OR t.receiver_id = %s)
        """
        params = [account_id, account_id]
        if start_date:
            query += " AND t.timestamp >= %s"
            params.append(start_date)
        if end_date:
            query += " AND t.timestamp <= %s"
            params.append(end_date)
        if risk_level in Transaction.RISK_LEVEL_RANGES:
            low, high = Transaction.RISK_LEVEL_RANGES[risk_level]
            query += " AND t.risk_score BETWEEN %s AND %s"
            params.extend([low, high])
        query += " ORDER BY t.timestamp DESC"

        cur = conn.cursor(dictionary=True)
        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def mark_resolved(conn, tx_id, staff_id):
        """Staff marks a flagged transaction as reviewed. Only meaningful
        for warned/blocked transactions, but not restricted here — the
        route decides what's sensible to show a "resolve" action on."""
        cur = conn.cursor()
        cur.execute(
            "UPDATE transactions SET resolved_by = %s, resolved_at = NOW() WHERE id = %s",
            (staff_id, tx_id),
        )
        conn.commit()
        cur.close()

    @staticmethod
    def bank_wide_daily_totals(conn, days=14):
        """Sum of all transaction amounts per day, bank-wide — feeds the
        Staff Dashboard's 'transactions over time' chart."""
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """SELECT DATE(`timestamp`) AS day, SUM(amount) AS total, COUNT(*) AS count
               FROM transactions
               WHERE `timestamp` >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
               GROUP BY DATE(`timestamp`)
               ORDER BY day ASC""",
            (days,),
        )
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def bank_wide_daily_avg_risk(conn, days=14):
        """Average risk score per day, bank-wide — feeds the Staff
        Dashboard's 'risk score trend' chart."""
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """SELECT DATE(`timestamp`) AS day, AVG(risk_score) AS avg_score
               FROM transactions
               WHERE `timestamp` >= DATE_SUB(CURDATE(), INTERVAL %s DAY)
               GROUP BY DATE(`timestamp`)
               ORDER BY day ASC""",
            (days,),
        )
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def flagged_vs_normal_counts(conn):
        """Bank-wide counts for the 'flagged vs normal' pie chart.
        'Flagged' = warned or blocked; 'normal' = allowed or confirmed."""
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """SELECT
                 SUM(CASE WHEN status IN ('warned', 'blocked') THEN 1 ELSE 0 END) AS flagged,
                 SUM(CASE WHEN status IN ('allowed', 'confirmed') THEN 1 ELSE 0 END) AS normal
               FROM transactions"""
        )
        row = cur.fetchone()
        cur.close()
        return {"flagged": row["flagged"] or 0, "normal": row["normal"] or 0}

    def to_dict(self):
        return {
            "id": self.id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "amount": str(self.amount),
            "timestamp": str(self.timestamp) if self.timestamp else None,
            "risk_score": self.risk_score,
            "status": self.status,
        }


# ======================================================================
# RiskAnalyzer — the "Intelligent Fraud Detection Layer"
# ======================================================================

class RiskAnalyzer:
    """
    Scores a prospective transfer from 0 (safe) to 100 (certainly fraud)
    using simple, explainable rules rather than a black-box model —
    each rule contributes points and a human-readable reason, which is
    what gets written to risk_logs.

    Thresholds (per spec):
        0–40   -> allow
        40–70  -> warn, require explicit confirmation
        70–100 -> block outright
    """

    ALLOW_MAX = 40
    WARN_MAX = 70

    LARGE_AMOUNT_ABSOLUTE = Decimal("50000")   # flat "this is just a lot of money" line
    NEW_RECEIVER_POINTS = 25
    FREQUENCY_WINDOW_MINUTES = 60
    FREQUENCY_THRESHOLD = 3                    # transfers within the window
    FREQUENCY_POINTS = 20
    LARGE_AMOUNT_POINTS = 30
    PATTERN_MULTIPLIER_POINTS = 25             # amount far above the sender's own average

    def __init__(self, conn):
        self.conn = conn

    # What a customer can do about each factor (shown on the Transfer page only)
    TIPS = {
        "INSUFFICIENT_BALANCE": "Add funds to your account or send a smaller amount.",
        "AMOUNT_VS_AVERAGE": "Send a smaller amount, or split it into a few smaller transfers over time.",
        "LARGE_FIRST": "Make a smaller first transfer to build up your account history.",
        "LARGE_AMOUNT": "Transfers of this size are always checked. Try a smaller amount.",
        "NEW_RECEIVER": "Send a small amount to this receiver first; later transfers will score lower.",
        "HIGH_FREQUENCY": "Wait a while before making another transfer.",
    }

    def analyze(self, sender_account, receiver_account, amount):
        """Returns (score: int 0-100, factors: list[dict]).

        Every factor that applies is listed with the exact points it adds, so
        the score is fully explainable:
            score = min(100, sum of the factors' points)
        Each factor dict has: code, title, detail, points.
        """
        factors = []

        def add(code, title, detail, points):
            factors.append({"code": code, "title": title, "detail": detail, "points": points})

        history = Transaction.history_for_sender(self.conn, sender_account.id)

        # Factor: not enough money in the account -> always blocked
        if amount > sender_account.balance:
            add("INSUFFICIENT_BALANCE", "Insufficient balance",
                f"You are sending {as_currency(amount)} but the account holds only "
                f"{as_currency(sender_account.balance)}.",
                100)

        # Factor: amount vs the sender's own average (completed transfers only)
        if history:
            past_amounts = [Decimal(str(h["amount"])) for h in history]
            average = sum(past_amounts) / len(past_amounts)
            if average > 0 and amount > average * 3:
                ratio = amount / average
                add("AMOUNT_VS_AVERAGE", "Unusually large for this account",
                    f"{as_currency(amount)} is {ratio:.1f}x your average transfer of "
                    f"{as_currency(average)} (flagged above 3x).",
                    self.PATTERN_MULTIPLIER_POINTS)
        elif amount > self.LARGE_AMOUNT_ABSOLUTE / 2:
            add("LARGE_FIRST", "Large amount with no history",
                f"{as_currency(amount)} is a large amount (over "
                f"{as_currency(self.LARGE_AMOUNT_ABSOLUTE / 2)}) and this account has no "
                f"completed transfers yet.",
                10)

        # Factor: flat large-amount limit
        if amount >= self.LARGE_AMOUNT_ABSOLUTE:
            add("LARGE_AMOUNT", "Above the large-amount limit",
                f"{as_currency(amount)} is at or above the {as_currency(self.LARGE_AMOUNT_ABSOLUTE)} "
                f"limit for a single transfer.",
                self.LARGE_AMOUNT_POINTS)

        # Factor: first payment to this receiver
        if not any(h["receiver_id"] == receiver_account.id for h in history):
            add("NEW_RECEIVER", "New receiver",
                "This account has never completed a transfer to this receiver before.",
                self.NEW_RECEIVER_POINTS)

        # Factor: many transfers in a short time
        recent = Transaction.recent_for_account(
            self.conn, sender_account.id, within_minutes=self.FREQUENCY_WINDOW_MINUTES
        )
        if len(recent) >= self.FREQUENCY_THRESHOLD:
            add("HIGH_FREQUENCY", "Many transfers in a short time",
                f"{len(recent)} transfers were already attempted from this account in the "
                f"last {self.FREQUENCY_WINDOW_MINUTES} minutes (flagged at "
                f"{self.FREQUENCY_THRESHOLD} or more).",
                self.FREQUENCY_POINTS)

        score = max(0, min(100, sum(f["points"] for f in factors)))
        return score, factors

    def decision_for(self, score):
        if score < self.ALLOW_MAX:
            return "allowed"
        if score < self.WARN_MAX:
            return "warned"
        return "blocked"

    def log(self, transaction_id, factors, score):
        """Store one risk_logs row per factor, with the exact points it added."""
        cur = self.conn.cursor()
        rows = factors or [{"code": "NONE", "title": "No risk signals",
                            "detail": "No abnormal signals detected.", "points": 0}]
        for f in rows:
            cur.execute(
                """INSERT INTO risk_logs (transaction_id, reason, score, points, rule_code, title)
                   VALUES (%s, %s, %s, %s, %s, %s)""",
                (transaction_id, f["detail"], score, f["points"], f["code"], f["title"]),
            )
        self.conn.commit()
        cur.close()


# ======================================================================
# Feedback
# ======================================================================

class Feedback:
    """A customer's rating of either a specific Staff member ('staff')
    or the banking service in general ('service'). staff_id is NULL
    for 'service' feedback."""

    def __init__(self, id=None, customer_id=None, staff_id=None, type=None,
                 rating=None, comment=None, created_at=None):
        self.id = id
        self.customer_id = customer_id
        self.staff_id = staff_id
        self.type = type
        self.rating = rating
        self.comment = comment
        self.created_at = created_at

    @staticmethod
    def create(conn, customer_id, feedback_type, rating, comment, staff_id=None, answers=None):
        """Store feedback.

        Pass `answers` = {question_no: 1..5} (all 10 questions) for both
        'staff' and 'service' feedback. The stored rating is their average
        (exact value in `score`, rounded 1-5 in `rating`). Without answers
        a single `rating` is stored (old-style feedback).
        """
        if feedback_type not in ("staff", "service"):
            raise ValueError("Feedback type must be 'staff' or 'service'.")
        if feedback_type == "staff" and not staff_id:
            raise ValueError("A staff member must be selected for staff feedback.")

        score = None
        if answers:
            values = [int(v) for v in answers.values()]
            if any(not (1 <= v <= 5) for v in values):
                raise ValueError("Every rating must be between 1 and 5.")
            score = round(sum(values) / len(values), 2)
            rating = int(score + 0.5)  # round half up -> 1..5
        if not (1 <= int(rating) <= 5):
            raise ValueError("Rating must be between 1 and 5.")

        cur = conn.cursor()
        cur.execute(
            """INSERT INTO feedback (customer_id, staff_id, type, rating, score, comment)
               VALUES (%s, %s, %s, %s, %s, %s)""",
            (customer_id, staff_id if feedback_type == "staff" else None,
             feedback_type, rating, score, comment),
        )
        feedback_id = cur.lastrowid
        if answers:
            cur.executemany(
                "INSERT INTO feedback_answers (feedback_id, question_no, rating) VALUES (%s, %s, %s)",
                [(feedback_id, int(q), int(v)) for q, v in answers.items()],
            )
        conn.commit()
        cur.close()
        return feedback_id

    @staticmethod
    def question_averages_for_staff(conn, staff_id):
        """{question_no: (average, number_of_answers)} for one staff member."""
        cur = conn.cursor()
        cur.execute(
            """SELECT fa.question_no, AVG(fa.rating), COUNT(*)
               FROM feedback_answers fa
               JOIN feedback f ON f.id = fa.feedback_id
               WHERE f.staff_id = %s AND f.type = 'staff'
               GROUP BY fa.question_no""",
            (staff_id,),
        )
        rows = cur.fetchall()
        cur.close()
        return {int(q): (float(avg), int(n)) for q, avg, n in rows}

    @staticmethod
    def question_averages_for_service(conn):
        """{question_no: (average, number_of_answers)} for general service feedback."""
        cur = conn.cursor()
        cur.execute(
            """SELECT fa.question_no, AVG(fa.rating), COUNT(*)
               FROM feedback_answers fa
               JOIN feedback f ON f.id = fa.feedback_id
               WHERE f.type = 'service'
               GROUP BY fa.question_no"""
        )
        rows = cur.fetchall()
        cur.close()
        return {int(q): (float(avg), int(n)) for q, avg, n in rows}

    @staticmethod
    def service_summary(conn):
        """(overall average, number of service reviews)."""
        cur = conn.cursor()
        cur.execute(
            "SELECT AVG(COALESCE(score, rating)), COUNT(*) FROM feedback WHERE type = 'service'"
        )
        avg, n = cur.fetchone()
        cur.close()
        return (float(avg) if avg is not None else None, int(n or 0))

    @staticmethod
    def for_customer(conn, customer_id):
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """SELECT f.*, su.name AS staff_name
               FROM feedback f
               LEFT JOIN users su ON su.id = f.staff_id
               WHERE f.customer_id = %s
               ORDER BY f.created_at DESC""",
            (customer_id,),
        )
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def for_staff(conn, staff_id):
        """All feedback left about a specific staff member."""
        cur = conn.cursor(dictionary=True)
        cur.execute(
            """SELECT f.*, cu.name AS customer_name
               FROM feedback f
               JOIN users cu ON cu.id = f.customer_id
               WHERE f.staff_id = %s AND f.type = 'staff'
               ORDER BY f.created_at DESC""",
            (staff_id,),
        )
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def all(conn, min_rating=None, feedback_type=None, start_date=None, end_date=None):
        """Global feedback listing for the Admin dashboard, with optional filters."""
        query = """
            SELECT f.*, cu.name AS customer_name, su.name AS staff_name
            FROM feedback f
            JOIN users cu ON cu.id = f.customer_id
            LEFT JOIN users su ON su.id = f.staff_id
            WHERE 1=1
        """
        params = []
        if min_rating:
            query += " AND f.rating >= %s"
            params.append(min_rating)
        if feedback_type in ("staff", "service"):
            query += " AND f.type = %s"
            params.append(feedback_type)
        if start_date:
            query += " AND f.created_at >= %s"
            params.append(start_date)
        if end_date:
            query += " AND f.created_at <= %s"
            params.append(end_date)
        query += " ORDER BY f.created_at DESC"

        cur = conn.cursor(dictionary=True)
        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        cur.close()
        return rows

    @staticmethod
    def average_rating_for_staff(conn, staff_id):
        cur = conn.cursor()
        cur.execute(
            "SELECT AVG(COALESCE(score, rating)) FROM feedback WHERE staff_id = %s AND type = 'staff'",
            (staff_id,),
        )
        avg = cur.fetchone()[0]
        cur.close()
        return float(avg) if avg is not None else None