# Ledgerline — Intelligent Online Banking System

A full-stack banking app (Flask + MySQL) with role-based access,
fund transfers, and a rule-based fraud-detection layer that scores
every transfer before it goes through.

## 1. Requirements

- Python 3.10+
- MySQL 8.x (running locally or reachable over the network)

## 2. Configure the connection

Open **app.py** and edit the `MYSQL_CONFIG` dictionary near the top
with your MySQL host, user, and password:

```python
MYSQL_CONFIG = {
    "host": "localhost",
    "port": 3306,
    "user": "root",
    "password": "your_mysql_password",
    "database": "ledgerline",
}
```

No `.env` file is used, per project requirements — credentials live
directly in `app.py`.

## 3. Install dependencies and run

```bash
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
python app.py
```

There's no separate "import the schema" step — the first time
`app.py` runs, `initialize_database()` connects to your MySQL server,
creates the `ledgerline` database if it doesn't exist yet, and creates
all four tables with `CREATE TABLE IF NOT EXISTS`. Restarting the app
later is always safe; it won't touch existing data. `schema.sql` is
still included as a plain reference of the same schema, in case you
ever want to inspect or apply it by hand.

The app starts at `http://localhost:5000`.

## 4. First-time setup: create the Admin

Visit `http://localhost:5000/setup-admin` once, right after starting
the app. This page creates the bank's single Admin account and then
disables itself — trying to visit it again (or calling
`Admin.bootstrap()` again) is refused once an Admin row exists, so
there is never more than one Admin.

**Logging in is role-specific — there are three separate login pages,
not one shared form:**

| Role     | Login page          | Who can log in there                          |
|----------|----------------------|------------------------------------------------|
| Customer | `/login`              | Customer accounts only                          |
| Staff    | `/staff/login`        | Staff accounts only                             |
| Admin    | `/admin/login`        | The single Admin account only                   |

Each page rejects the wrong role's credentials outright — logging in
with a Staff email on `/login`, for example, gets "This login page
isn't for your account type," not a silent success. All three pages
link to each other and to `/register`, so a visitor never gets stuck
on the wrong one.

Customers register themselves at `/register`. **Admin can create
both Customer and Staff accounts** from the Admin Console (`/admin`)
after logging in — customers aren't limited to self-registration,
Admin can open an account on their behalf too, in addition to the
self-serve path.

## 5. Project structure

```
banking_system/
├── app.py             # Flask app factory + MySQL connection pool (config lives here)
├── models.py          # OOP domain classes: User/Admin/Staff/Customer, Account,
│                       # Transaction, RiskAnalyzer, Feedback
├── routes.py          # All HTTP routes (Blueprint), thin — delegates to models/services
├── services.py        # Service layer: PDF generation, staff performance, chart data
├── utils.py           # Password hashing, auth decorators, formatting helpers
├── schema.sql          # MySQL schema (reference — app.py applies it automatically)
├── requirements.txt
├── templates/          # Jinja2 templates
└── static/
    ├── css/style.css   # Design system: light + dark theme via CSS variables
    └── js/main.js      # Theme toggle (persisted in localStorage)
```

## 6. Feature guide

**Customer**
- `/transfer`, `/history` (with PDF download via `/history/pdf`, using reportlab)
- `/change-password` — old password check, bcrypt-hashed new password
- `/feedback` — rate a specific Staff member or the service in general (1–5),
  plus a history of feedback you've left

**Staff** (`/staff/dashboard`)
- High-risk account count, flagged transaction count
- Three Chart.js graphs: transactions over time, risk-score trend, flagged
  vs normal (pie) — bank-wide, fed by `/staff/api/charts`
- Clickable account list → `/staff/account/<id>` deep view: full transaction
  history for that account, filterable by date range and risk level
  (low/medium/high), with a "Mark reviewed" action on flagged transactions
  (this is what feeds Admin's resolution-speed metric)
- Feedback left about them, read-only

**Admin**
- `/admin` — create Staff *and* Customer accounts, all-users list, flagged
  transactions, high-risk accounts
- `/admin/performance` — ranking table + bar chart of every Staff member's
  flagged-transactions-resolved count, average resolution time, average
  customer rating, and an auto-assigned Gold/Silver/Bronze reward tier
  (see `services.reward_tier()` for the thresholds — tune freely)
- `/admin/feedback` — every piece of feedback in the bank, filterable by
  type, minimum rating, and date range

## 7. How the fraud-detection layer works

`RiskAnalyzer.analyze()` (in `models.py`) runs five simple,
explainable rules against every prospective transfer and sums their
points into a 0–100 score:

| Signal                                             | Points |
|-----------------------------------------------------|--------|
| Amount > 3x the sender's own historical average      | 25     |
| Amount ≥ flat large-amount threshold (₹50,000)       | 30     |
| First-ever transfer to this receiver                 | 25     |
| 3+ transfers from this account in the last hour      | 20     |
| Amount exceeds current balance                        | forces score to 100 |

The score maps to a decision:

- **0–40 → Allowed** — the transfer executes immediately.
- **40–70 → Warned** — the transfer is held; the customer sees the
  specific reasons and must explicitly confirm before it executes.
- **70–100 → Blocked** — the transfer is refused outright and logged.

Every score's contributing reasons are written to `risk_logs`, and
the Admin Console lists every transaction scoring 40+ so staff/admin
can review flagged activity and spot high-risk accounts.

## 8. Security notes

- Passwords are hashed with bcrypt — never stored or logged in plaintext.
- Balance updates run inside a single DB transaction with a row lock
  (`SELECT ... FOR UPDATE`) so two simultaneous transfers can't both
  read a stale balance.
- Sessions are HttpOnly + SameSite=Lax cookies; routes are protected
  with `@login_required` / `@role_required` decorators.
- Each login route checks the account's actual role after the password
  verifies, so a valid Customer password entered on `/admin/login`
  still gets rejected — credentials alone don't grant cross-role access.
- Change `SECRET_KEY` and `MYSQL_CONFIG` before deploying anywhere
  beyond your own machine — the defaults here are for local dev only.
