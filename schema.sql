-- =====================================================================
--  Ledgerline — Intelligent Online Banking System
--  Reference copy of the MySQL schema. You don't need to run this by
--  hand — app.py creates the `ledgerline` database and these same
--  four tables automatically the first time it starts. This file is
--  kept for readability, or if you'd rather apply it manually:
--      mysql -u root -p < schema.sql
-- =====================================================================

CREATE DATABASE IF NOT EXISTS ledgerline
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE ledgerline;

-- ---------------------------------------------------------------------
-- users : one row per human account holder (Admin / Staff / Customer)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(120)  NOT NULL,
    email         VARCHAR(180)  NOT NULL UNIQUE,
    password      VARCHAR(255)  NOT NULL,          -- bcrypt hash, never plaintext
    role          ENUM('admin', 'staff', 'customer') NOT NULL DEFAULT 'customer',
    created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_active     TINYINT(1)    NOT NULL DEFAULT 1,

    INDEX idx_users_role (role)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- accounts : one row per bank account. A user could in principle hold
-- more than one, so this stays a separate table rather than columns
-- bolted onto users.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS accounts (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    user_id        INT NOT NULL,
    account_number VARCHAR(20) NOT NULL UNIQUE,
    balance        DECIMAL(14, 2) NOT NULL DEFAULT 0.00,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_accounts_user
        FOREIGN KEY (user_id) REFERENCES users(id)
        ON DELETE CASCADE,

    CONSTRAINT chk_balance_non_negative CHECK (balance >= 0),

    INDEX idx_accounts_user (user_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- transactions : one row per transfer attempt (allowed, warned or
-- blocked). status / risk_score come from the RiskAnalyzer.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS transactions (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    sender_id     INT NOT NULL,
    receiver_id   INT NOT NULL,
    amount        DECIMAL(14, 2) NOT NULL,
    `timestamp`   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    risk_score    INT NOT NULL DEFAULT 0,
    status        ENUM('allowed', 'warned', 'blocked', 'confirmed') NOT NULL DEFAULT 'allowed',

    CONSTRAINT fk_tx_sender
        FOREIGN KEY (sender_id) REFERENCES accounts(id),
    CONSTRAINT fk_tx_receiver
        FOREIGN KEY (receiver_id) REFERENCES accounts(id),
    CONSTRAINT chk_amount_positive CHECK (amount > 0),

    INDEX idx_tx_sender (sender_id),
    INDEX idx_tx_receiver (receiver_id),
    INDEX idx_tx_timestamp (`timestamp`)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- risk_logs : the reasoning behind each transaction's risk score,
-- one row per contributing factor so the admin dashboard can explain
-- *why* something was flagged, not just that it was.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS risk_logs (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    transaction_id INT NOT NULL,
    reason         VARCHAR(255) NOT NULL,
    score          INT NOT NULL,
    created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_risklog_tx
        FOREIGN KEY (transaction_id) REFERENCES transactions(id)
        ON DELETE CASCADE,

    INDEX idx_risklog_tx (transaction_id)
) ENGINE=InnoDB;

-- ---------------------------------------------------------------------
-- Staff-review columns on transactions: who resolved a flagged
-- transaction, and when. Used to compute staff resolution speed.
-- ---------------------------------------------------------------------
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS resolved_by INT NULL;
ALTER TABLE transactions ADD COLUMN IF NOT EXISTS resolved_at DATETIME NULL;

-- ---------------------------------------------------------------------
-- feedback : customer feedback, either about a specific Staff member
-- or about the banking service in general (staff_id is NULL for
-- 'service' feedback).
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS feedback (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    customer_id   INT NOT NULL,
    staff_id      INT NULL,
    type          ENUM('staff', 'service') NOT NULL,
    rating        TINYINT NOT NULL,
    comment       TEXT,
    created_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_feedback_customer
        FOREIGN KEY (customer_id) REFERENCES users(id)
        ON DELETE CASCADE,
    CONSTRAINT fk_feedback_staff
        FOREIGN KEY (staff_id) REFERENCES users(id)
        ON DELETE SET NULL,
    CONSTRAINT chk_feedback_rating CHECK (rating BETWEEN 1 AND 5),

    INDEX idx_feedback_type (type),
    INDEX idx_feedback_staff (staff_id)
) ENGINE=InnoDB;


-- ----------------------------------------------------------------------
-- feedback_answers : per-question star ratings (10 questions) a customer
-- gives when rating a Staff member. feedback.score holds their exact
-- average; feedback.rating holds it rounded to 1-5.
-- (app.py adds feedback.score automatically on existing databases; for a
--  manual setup run:  ALTER TABLE feedback ADD COLUMN score DECIMAL(3,2) NULL;)
-- ----------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS feedback_answers (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    feedback_id   INT NOT NULL,
    question_no   TINYINT NOT NULL,
    rating        TINYINT NOT NULL,
    CONSTRAINT fk_fa_feedback FOREIGN KEY (feedback_id) REFERENCES feedback(id) ON DELETE CASCADE,
    CONSTRAINT chk_fa_rating CHECK (rating BETWEEN 1 AND 5),
    UNIQUE KEY uq_fa_feedback_question (feedback_id, question_no)
) ENGINE=InnoDB;


-- ----------------------------------------------------------------------
-- Phone number + UPI ID, and how a transfer was addressed.
-- (app.py adds these automatically on startup; run manually only if you
--  set the database up by hand.)
-- ----------------------------------------------------------------------
ALTER TABLE users ADD COLUMN phone  VARCHAR(10) NULL;
ALTER TABLE users ADD COLUMN upi_id VARCHAR(60) NULL;
ALTER TABLE users ADD UNIQUE INDEX uq_users_phone (phone);
ALTER TABLE users ADD UNIQUE INDEX uq_users_upi_id (upi_id);
ALTER TABLE transactions ADD COLUMN transfer_method VARCHAR(10) NOT NULL DEFAULT 'account';
ALTER TABLE transactions ADD COLUMN receiver_ref    VARCHAR(60) NULL;

-- Second UPI ID, created from the customer's email address
-- (app.py adds it and fills it for existing customers automatically).
ALTER TABLE users ADD COLUMN upi_email VARCHAR(160) NULL;
ALTER TABLE users ADD UNIQUE INDEX uq_users_upi_email (upi_email);

-- Per-factor risk breakdown (app.py adds these automatically on startup)
ALTER TABLE risk_logs ADD COLUMN points    INT NULL;
ALTER TABLE risk_logs ADD COLUMN rule_code VARCHAR(40) NULL;
ALTER TABLE risk_logs ADD COLUMN title     VARCHAR(80) NULL;

-- Account closure ("delete"): when and by whom (app.py adds these automatically)
ALTER TABLE users ADD COLUMN deleted_at DATETIME NULL;
ALTER TABLE users ADD COLUMN deleted_by INT NULL;

-- Login history (drives the green "login activity" calendar). app.py creates it automatically.
CREATE TABLE IF NOT EXISTS login_events (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_id       INT NOT NULL,
    logged_in_at  DATETIME NOT NULL,
    CONSTRAINT fk_login_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    INDEX idx_login_user_time (user_id, logged_in_at)
) ENGINE=InnoDB;