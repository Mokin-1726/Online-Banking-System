"""
Ledgerline — Intelligent Online Banking System
Entry point: creates the Flask app, auto-provisions the MySQL schema,
wires up a connection pool, and registers routes.

NOTE ON CONFIG: per project requirement this app takes its MySQL
credentials directly here rather than from a .env file. Change the
MYSQL_CONFIG block below to match your local database before running.

NOTE ON SCHEMA: there is no manual "run schema.sql first" step. The
first time this file runs, initialize_database() below creates the
`ledgerline` database and all four tables itself, using
CREATE DATABASE/TABLE IF NOT EXISTS — so it's safe to restart the app
any number of times. schema.sql is kept alongside this file purely as
a readable reference of the same schema, in case you want to inspect
or apply it by hand.
"""

import os
from datetime import timedelta

from flask import Flask
import mysql.connector
from mysql.connector import pooling

import security_module   # suspicious-activity module: its tables and columns are created below

# --------------------------------------------------------------------
# MySQL connection settings — edit these for your environment.
# --------------------------------------------------------------------
# Your MySQL password lives in a separate file, local_config.py, so replacing
# app.py never wipes it. Create it once next to app.py with this one line:
#     MYSQL_PASSWORD = "your real password"
# (or set the MYSQL_PASSWORD environment variable instead).
try:
    from local_config import MYSQL_PASSWORD
except ImportError:
    MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "your_mysql_password")

MYSQL_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": MYSQL_PASSWORD,
    "database": "ledgerline",
}

DB_NAME = MYSQL_CONFIG["database"]

# Same four tables as schema.sql, expressed here so app.py is fully
# self-contained and the schema is applied automatically on startup.
_SCHEMA_STATEMENTS = [
    """
    CREATE TABLE IF NOT EXISTS users (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        name          VARCHAR(120)  NOT NULL,
        email         VARCHAR(180)  NOT NULL UNIQUE,
        password      VARCHAR(255)  NOT NULL,
        role          ENUM('admin', 'staff', 'customer') NOT NULL DEFAULT 'customer',
        created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
        is_active     TINYINT(1)    NOT NULL DEFAULT 1,
        INDEX idx_users_role (role)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE IF NOT EXISTS accounts (
        id             INT AUTO_INCREMENT PRIMARY KEY,
        user_id        INT NOT NULL,
        account_number VARCHAR(20) NOT NULL UNIQUE,
        balance        DECIMAL(14, 2) NOT NULL DEFAULT 0.00,
        created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_accounts_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT chk_balance_non_negative CHECK (balance >= 0),
        INDEX idx_accounts_user (user_id)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE IF NOT EXISTS transactions (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        sender_id     INT NOT NULL,
        receiver_id   INT NOT NULL,
        amount        DECIMAL(14, 2) NOT NULL,
        `timestamp`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        risk_score    INT NOT NULL DEFAULT 0,
        status        ENUM('allowed', 'warned', 'blocked', 'confirmed') NOT NULL DEFAULT 'allowed',
        CONSTRAINT fk_tx_sender FOREIGN KEY (sender_id) REFERENCES accounts(id),
        CONSTRAINT fk_tx_receiver FOREIGN KEY (receiver_id) REFERENCES accounts(id),
        CONSTRAINT chk_amount_positive CHECK (amount > 0),
        INDEX idx_tx_sender (sender_id),
        INDEX idx_tx_receiver (receiver_id),
        INDEX idx_tx_timestamp (`timestamp`)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE IF NOT EXISTS risk_logs (
        id             INT AUTO_INCREMENT PRIMARY KEY,
        transaction_id INT NOT NULL,
        reason         VARCHAR(255) NOT NULL,
        score          INT NOT NULL,
        created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_risklog_tx FOREIGN KEY (transaction_id) REFERENCES transactions(id) ON DELETE CASCADE,
        INDEX idx_risklog_tx (transaction_id)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE IF NOT EXISTS feedback (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        customer_id   INT NOT NULL,
        staff_id      INT NULL,
        type          ENUM('staff', 'service') NOT NULL,
        rating        TINYINT NOT NULL,
        comment       TEXT,
        created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT fk_feedback_customer FOREIGN KEY (customer_id) REFERENCES users(id) ON DELETE CASCADE,
        CONSTRAINT fk_feedback_staff FOREIGN KEY (staff_id) REFERENCES users(id) ON DELETE SET NULL,
        CONSTRAINT chk_feedback_rating CHECK (rating BETWEEN 1 AND 5),
        INDEX idx_feedback_type (type),
        INDEX idx_feedback_staff (staff_id)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE IF NOT EXISTS login_events (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        user_id       INT NOT NULL,
        logged_in_at  DATETIME NOT NULL,
        CONSTRAINT fk_login_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX idx_login_user_time (user_id, logged_in_at)
    ) ENGINE=InnoDB
    """,
    """
    CREATE TABLE IF NOT EXISTS feedback_answers (
        id            INT AUTO_INCREMENT PRIMARY KEY,
        feedback_id   INT NOT NULL,
        question_no   TINYINT NOT NULL,
        rating        TINYINT NOT NULL,
        CONSTRAINT fk_fa_feedback FOREIGN KEY (feedback_id) REFERENCES feedback(id) ON DELETE CASCADE,
        CONSTRAINT chk_fa_rating CHECK (rating BETWEEN 1 AND 5),
        UNIQUE KEY uq_fa_feedback_question (feedback_id, question_no)
    ) ENGINE=InnoDB
    """,
]

# Suspicious-activity module tables (security_challenges, secure_confirmation_attempts,
# staff_alerts, security_notifications) — created after the tables they reference.
_SCHEMA_STATEMENTS += security_module.SCHEMA_STATEMENTS

# Columns added to the original `transactions` table to support staff
# review workflows (who resolved a flagged transaction, and when — used
# to compute resolution speed for staff performance). Added via
# ALTER ... ADD COLUMN IF NOT EXISTS so existing databases from before
# this feature pick them up automatically, without a manual migration.
# NOTE: "ADD COLUMN IF NOT EXISTS" is MariaDB-only syntax; MySQL 8 rejects
# it. So we check information_schema first and only ALTER when needed.
_ALTER_COLUMNS = [
    ("transactions", "resolved_by", "INT NULL"),
    ("transactions", "resolved_at", "DATETIME NULL"),
    # exact average of the 10 staff-question ratings (feedback.rating keeps
    # the rounded 1-5 value so older screens/filters keep working)
    ("feedback", "score", "DECIMAL(3,2) NULL"),
    # phone number + UPI ID (the UPI ID is generated from the phone number)
    ("users", "phone", "VARCHAR(10) NULL"),
    ("users", "upi_id", "VARCHAR(60) NULL"),
    # second UPI ID, created from the customer's email address
    ("users", "upi_email", "VARCHAR(160) NULL"),
    # account closure ("delete"): when and by whom
    ("users", "deleted_at", "DATETIME NULL"),
    ("users", "deleted_by", "INT NULL"),
    # how the sender addressed the receiver: 'account' | 'upi' | 'phone',
    # and the exact account number / UPI ID / phone number they used
    ("transactions", "transfer_method", "VARCHAR(10) NOT NULL DEFAULT 'account'"),
    ("transactions", "receiver_ref", "VARCHAR(60) NULL"),
    # per-factor breakdown of a risk score: which rule, and the points it added
    ("risk_logs", "points", "INT NULL"),
    ("risk_logs", "rule_code", "VARCHAR(40) NULL"),
    ("risk_logs", "title", "VARCHAR(80) NULL"),
]

# users.high_security_password (hash) for the secure-confirmation step
_ALTER_COLUMNS += security_module.ALTER_COLUMNS

# (table, index name, column) — one phone number / UPI ID per customer.
# NULLs are allowed many times, so customers without a phone still work.
_UNIQUE_INDEXES = [
    ("users", "uq_users_phone", "phone"),
    ("users", "uq_users_upi_id", "upi_id"),
    ("users", "uq_users_upi_email", "upi_email"),
]


def initialize_database():
    """Create the database (if missing) and all tables (if missing).

    Runs once at import time, before the connection pool is created,
    so `python app.py` is the only setup step needed beyond editing
    MYSQL_CONFIG.
    """
    server_config = {k: v for k, v in MYSQL_CONFIG.items() if k != "database"}

    conn = mysql.connector.connect(**server_config)
    try:
        cur = conn.cursor()
        cur.execute(
            f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"
        )
        cur.close()
    finally:
        conn.close()

    conn = mysql.connector.connect(database=DB_NAME, **server_config)
    try:
        cur = conn.cursor()
        for statement in _SCHEMA_STATEMENTS:
            cur.execute(statement)
        for table, column, definition in _ALTER_COLUMNS:
            cur.execute(
                "SELECT COUNT(*) FROM information_schema.COLUMNS "
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s",
                (DB_NAME, table, column),
            )
            if cur.fetchone()[0] == 0:
                cur.execute(f"ALTER TABLE `{table}` ADD COLUMN `{column}` {definition}")
        for table, index_name, column in _UNIQUE_INDEXES:
            cur.execute(
                "SELECT COUNT(*) FROM information_schema.STATISTICS "
                "WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND INDEX_NAME = %s",
                (DB_NAME, table, index_name),
            )
            if cur.fetchone()[0] == 0:
                cur.execute(f"ALTER TABLE `{table}` ADD UNIQUE INDEX `{index_name}` (`{column}`)")

        # Existing customers get their email-based UPI ID (abc@ledgerline).
        # Customers who have none yet, or still have the older long format
        # (abc.gmail.com@ledgerline), are (re)generated. IDs already in the
        # short format are never touched, so nobody's UPI ID changes by surprise.
        from utils import make_email_upi_id, legacy_email_upi_id

        def needs_update(email, upi):
            return not upi or upi == legacy_email_upi_id(email)

        cur.execute("SELECT id, email, upi_email FROM users WHERE role = 'customer' ORDER BY id")
        customers = cur.fetchall()
        taken = {upi for _, email, upi in customers if not needs_update(email, upi)}
        cur.execute("SELECT upi_id FROM users WHERE upi_id IS NOT NULL")
        taken.update(upi for (upi,) in cur.fetchall())

        for user_id, email, upi in customers:
            if not needs_update(email, upi):
                continue
            candidate, n = make_email_upi_id(email), 1
            while candidate in taken:
                n += 1
                candidate = make_email_upi_id(email, str(n))
            taken.add(candidate)
            cur.execute("UPDATE users SET upi_email = %s WHERE id = %s", (candidate, user_id))
        conn.commit()
        cur.close()
    finally:
        conn.close()


# --------------------------------------------------------------------
# Provision the schema, then open a small connection pool. A pool
# avoids opening a new TCP connection to MySQL on every request while
# still giving every request its own connection (never shared across
# concurrent requests).
# --------------------------------------------------------------------
try:
    initialize_database()
    connection_pool = pooling.MySQLConnectionPool(
        pool_name="ledgerline_pool",
        pool_size=10,
        **MYSQL_CONFIG,
    )
    print(f"[ledgerline] Connected — database '{DB_NAME}' is ready.")
except mysql.connector.Error as err:
    connection_pool = None
    print("=" * 70)
    print(f"[ledgerline] ERROR: could not set up MySQL at startup: {err}")
    print("[ledgerline] Check MYSQL_CONFIG in app.py and that MySQL is running.")
    print("=" * 70)


def get_db_connection():
    """Return a live MySQL connection from the pool.

    Every route calls this once per request and closes the connection
    (returning it to the pool) when done — see routes.py.
    """
    if connection_pool is None:
        raise RuntimeError(
            "MySQL connection pool is not initialized. "
            "Check MYSQL_CONFIG in app.py."
        )
    return connection_pool.get_connection()


def create_app():
    app = Flask(__name__)

    # Session / secret key. In production, load this from a real secret
    # manager — a fixed dev fallback is fine for coursework/demo use.
    app.config["SECRET_KEY"] = os.environ.get(
        "LEDGERLINE_SECRET_KEY", "dev-secret-key-change-me"
    )
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=8)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

    from routes import bp as routes_bp
    app.register_blueprint(routes_bp)

    from security_routes import bp as security_bp
    app.register_blueprint(security_bp)

    return app


app = create_app()

if __name__ == "__main__":
    # debug=True is for local development only — turn off before deploying.
    app.run(debug=True, host="0.0.0.0", port=5000)