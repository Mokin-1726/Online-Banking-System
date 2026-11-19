"""
Service layer for Ledgerline.

Keeps "how do I compute/produce this" logic (PDF rendering, staff
performance scoring, reward tiers, chart datasets) out of routes.py,
which stays a thin HTTP layer, and out of models.py, which stays focused
on plain CRUD/query access to each table.
"""

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
)

from models import Transaction, Feedback, User
from utils import humanize_minutes


# ======================================================================
# 2.1 — Statement PDF
# ======================================================================

def generate_pdf_statement(account, transactions, start_date=None, end_date=None):
    """Build a PDF statement for one account and return it as a BytesIO
    buffer, ready to send with Flask's send_file().

    `transactions` is the list of dict rows as returned by
    Transaction.for_account() / for_account_filtered() — each must have
    timestamp, sender_id, receiver_id, sender_account, receiver_account,
    amount, risk_score, status.
    """
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        topMargin=1.5 * cm, bottomMargin=1.5 * cm,
        leftMargin=1.5 * cm, rightMargin=1.5 * cm,
    )
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("Ledgerline — Account Statement", styles["Title"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Account number: {account.account_number}", styles["Normal"]))

    date_range = "All available history"
    if start_date or end_date:
        date_range = f"{start_date or 'earliest'} to {end_date or 'latest'}"
    story.append(Paragraph(f"Date range: {date_range}", styles["Normal"]))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}", styles["Normal"]
    ))
    story.append(Spacer(1, 14))

    table_data = [["Date", "Direction", "Counterparty", "Amount", "Risk", "Status"]]
    for tx in transactions:
        direction = "Sent" if tx["sender_id"] == account.id else "Received"
        counterparty = (
            tx["receiver_account"] if tx["sender_id"] == account.id else tx["sender_account"]
        )
        table_data.append([
            str(tx["timestamp"]),
            direction,
            counterparty,
            f"{float(tx['amount']):,.2f}",
            str(tx["risk_score"]),
            "Flagged" if tx["status"] in ("warned", "blocked") else "Allowed",
        ])

    if len(table_data) == 1:
        story.append(Paragraph("No transactions found for this range.", styles["Normal"]))
    else:
        table = Table(table_data, repeatRows=1, colWidths=[3.0*cm, 2.2*cm, 3.3*cm, 2.6*cm, 1.6*cm, 2.2*cm])
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0E8F86")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 8.5),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D9DEE6")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F6F8")]),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(table)

    doc.build(story)
    buffer.seek(0)
    return buffer


# ======================================================================
# 3.2 — Staff account deep view
# ======================================================================

def get_full_transaction_history(conn, account_id, start_date=None, end_date=None, risk_level=None):
    """Full, filterable transaction history for one account — used by
    the Staff account deep-view page. Thin wrapper so routes.py doesn't
    need to know which Transaction method backs it."""
    return Transaction.for_account_filtered(conn, account_id, start_date, end_date, risk_level)


# ======================================================================
# 4.1 — Staff performance + reward tiers
# ======================================================================

# ----------------------------------------------------------------------
# Staff performance score (0-100) and Gold / Silver / Bronze tiers
#
#   score = rating points (max 50) + volume points (max 30) + speed points (max 20)
#
#   rating  : average customer rating (from the 10-question feedback) / 5 x 50
#   volume  : flagged transactions resolved / VOLUME_TARGET x 30   (capped at 30)
#   speed   : full 20 points if the average resolution time is within
#             SPEED_FULL_MINUTES, falling to 0 at SPEED_ZERO_MINUTES
#
#   Gold   : score 75 or more        Silver : score 50 or more
#   Bronze : any activity below 50   Unranked: no resolved cases and no ratings yet
#   (A staff member who has resolved no flagged transaction yet can reach Bronze at most.)
#
# Tune the numbers below to match your own grading rubric.
# ----------------------------------------------------------------------

SCORE_MAX = {"rating": 50, "volume": 30, "speed": 20}
VOLUME_TARGET = 3                      # resolved cases needed for full volume points
SPEED_FULL_MINUTES = 60                # average resolution within 1 hour -> full points
SPEED_ZERO_MINUTES = 7 * 24 * 60       # a week or slower -> 0 points
GOLD_MIN_SCORE = 75
SILVER_MIN_SCORE = 50


def score_breakdown(avg_rating, resolved_count, avg_minutes):
    """Explainable performance score: the three parts, the total, the tier,
    and what is still needed for the next tier."""
    # MySQL AVG() hands back Decimal; do all the maths in plain floats
    avg_rating = float(avg_rating) if avg_rating is not None else None
    avg_minutes = float(avg_minutes) if avg_minutes is not None else None
    resolved_count = int(resolved_count or 0)

    rating_pts = round((avg_rating or 0) / 5 * SCORE_MAX["rating"], 1)
    volume_pts = round(min(resolved_count / VOLUME_TARGET, 1) * SCORE_MAX["volume"], 1)
    if avg_minutes is None:
        speed_pts = 0.0
    elif avg_minutes <= SPEED_FULL_MINUTES:
        speed_pts = float(SCORE_MAX["speed"])
    elif avg_minutes >= SPEED_ZERO_MINUTES:
        speed_pts = 0.0
    else:
        span = SPEED_ZERO_MINUTES - SPEED_FULL_MINUTES
        speed_pts = round(SCORE_MAX["speed"] * (1 - (avg_minutes - SPEED_FULL_MINUTES) / span), 1)
    total = round(rating_pts + volume_pts + speed_pts, 1)

    has_activity = resolved_count > 0 or avg_rating is not None
    if not has_activity:
        tier = "Unranked"
    elif resolved_count == 0:
        tier = "Bronze"                       # ratings only: Bronze at most
    elif total >= GOLD_MIN_SCORE:
        tier = "Gold"
    elif total >= SILVER_MIN_SCORE:
        tier = "Silver"
    else:
        tier = "Bronze"

    parts = [
        {"key": "rating", "label": "Customer rating", "points": rating_pts, "max": SCORE_MAX["rating"],
         "detail": (f"Average {avg_rating:.1f} / 5 from customer feedback" if avg_rating is not None
                    else "No customer ratings yet")},
        {"key": "volume", "label": "Cases resolved", "points": volume_pts, "max": SCORE_MAX["volume"],
         "detail": f"{resolved_count} flagged transaction(s) resolved (full points at {VOLUME_TARGET})"},
        {"key": "speed", "label": "Resolution speed", "points": speed_pts, "max": SCORE_MAX["speed"],
         "detail": (f"Average {humanize_minutes(avg_minutes)} per case (full points within "
                    f"{humanize_minutes(SPEED_FULL_MINUTES)}, none after "
                    f"{humanize_minutes(SPEED_ZERO_MINUTES)})" if avg_minutes is not None
                    else "No resolved cases yet")},
    ]
    for part in parts:
        part["pct"] = round(part["points"] / part["max"] * 100)

    # next tier
    if tier == "Gold":
        nxt = None
    elif tier == "Silver":
        nxt = {"name": "Gold", "need": GOLD_MIN_SCORE}
    elif tier == "Bronze" and resolved_count == 0:
        nxt = {"name": "Silver", "need": None}      # needs a resolved case first
    elif tier == "Bronze":
        nxt = {"name": "Silver", "need": SILVER_MIN_SCORE}
    else:
        nxt = {"name": "Bronze", "need": None}
    if nxt and nxt["need"] is not None:
        nxt["missing"] = round(max(nxt["need"] - total, 0), 1)
        nxt["pct"] = round(min(total / nxt["need"], 1) * 100)
    return {"total": total, "tier": tier, "parts": parts, "next": nxt,
            "capped": tier == "Bronze" and resolved_count == 0 and has_activity}


TIER_ORDER = ["Gold", "Silver", "Bronze", "Unranked"]


def calculate_staff_performance(conn):
    """One row per (active) Staff member: how many flagged transactions they've
    resolved, their average resolution speed (in minutes), their average
    customer rating, their performance score and Gold / Silver / Bronze tier.
    Sorted best first (highest score)."""
    staff_members = User.all_staff(conn)
    results = []

    cur = conn.cursor(dictionary=True)
    for staff in staff_members:
        cur.execute(
            """SELECT COUNT(*) AS resolved_count,
                      AVG(TIMESTAMPDIFF(SECOND, `timestamp`, resolved_at)) AS avg_seconds
               FROM transactions
               WHERE resolved_by = %s AND resolved_at IS NOT NULL""",
            (staff.id,),
        )
        row = cur.fetchone()
        resolved_count = row["resolved_count"] or 0
        avg_seconds = row["avg_seconds"]
        avg_minutes = round(float(avg_seconds) / 60, 1) if avg_seconds is not None else None

        avg_rating = Feedback.average_rating_for_staff(conn, staff.id)
        info = score_breakdown(avg_rating, resolved_count, avg_minutes)

        results.append({
            "staff_id": staff.id,
            "name": staff.name,
            "email": staff.email,
            "resolved_count": resolved_count,
            "avg_resolution_minutes": avg_minutes,
            "avg_rating": round(avg_rating, 2) if avg_rating is not None else None,
            "score": info["total"],
            "reward_tier": info["tier"],
            "score_info": info,
        })
    cur.close()

    results.sort(key=lambda r: (r["score"], r["resolved_count"]), reverse=True)
    return results


def group_by_tier(performance):
    """[(tier, [staff rows])] in Gold -> Silver -> Bronze -> Unranked order,
    leaving out tiers nobody is in."""
    groups = []
    for tier in TIER_ORDER:
        members = [p for p in performance if p["reward_tier"] == tier]
        if members:
            groups.append((tier, members))
    return groups


# ======================================================================
# Staff feedback questionnaire — shown to a customer when they rate a
# Staff member. Each is answered with 1-5 stars; the average is the
# staff member's rating. Edit the wording freely, but keep the numbers
# (they're stored with each answer).
# ======================================================================

STAFF_QUESTIONS = [
    {"no": 1,  "short": "Courtesy",        "text": "Was the staff member polite and courteous?"},
    {"no": 2,  "short": "Listening",       "text": "Did they listen carefully and understand your issue?"},
    {"no": 3,  "short": "Knowledge",       "text": "How well did they know the banking products and process?"},
    {"no": 4,  "short": "Clarity",         "text": "Were their explanations clear and easy to understand?"},
    {"no": 5,  "short": "Speed",           "text": "How quickly did they resolve your issue?"},
    {"no": 6,  "short": "Accuracy",        "text": "Was the information and help they gave accurate?"},
    {"no": 7,  "short": "Professionalism", "text": "How professional was their behaviour?"},
    {"no": 8,  "short": "Patience",        "text": "Were they patient with your questions?"},
    {"no": 9,  "short": "Follow-up",       "text": "Did they keep you informed and follow up when needed?"},
    {"no": 10, "short": "Overall",         "text": "Overall, how satisfied are you with this staff member?"},
]


# ----------------------------------------------------------------------
# General banking-service questionnaire (customer picks "Banking service")
# ----------------------------------------------------------------------

SERVICE_QUESTIONS = [
    {"no": 1,  "short": "Ease of use",    "text": "How easy is it to use our online banking?"},
    {"no": 2,  "short": "Speed",          "text": "How fast and smooth are your transfers and transactions?"},
    {"no": 3,  "short": "Security",       "text": "How safe and secure do you feel with your account?"},
    {"no": 4,  "short": "Fees",           "text": "How transparent and fair are our fees and charges?"},
    {"no": 5,  "short": "Statements",     "text": "How clear and easy to understand are your statements?"},
    {"no": 6,  "short": "Reliability",    "text": "How reliable is the service (few errors or downtime)?"},
    {"no": 7,  "short": "Support",        "text": "How available and helpful is customer support?"},
    {"no": 8,  "short": "Problem solving", "text": "How easily are your problems or disputes resolved?"},
    {"no": 9,  "short": "Fraud alerts",   "text": "How good is our fraud protection and warnings?"},
    {"no": 10, "short": "Overall",        "text": "Overall, how satisfied are you with our banking service?"},
]


def get_service_performance(conn):
    """Admin view of general-service feedback: overall average, per-question
    averages, strongest / weakest area and radar-chart data."""
    avg, count = Feedback.service_summary(conn)
    q_avgs = Feedback.question_averages_for_service(conn)
    questions = []
    for q in SERVICE_QUESTIONS:
        qa, n = q_avgs.get(q["no"], (None, 0))
        questions.append({
            "no": q["no"], "short": q["short"], "text": q["text"],
            "avg": round(qa, 2) if qa is not None else None,
            "count": n,
            "pct": round(qa / 5 * 100) if qa is not None else 0,
        })
    answered = [q for q in questions if q["avg"] is not None]
    strongest = max(answered, key=lambda q: q["avg"]) if answered else None
    weakest = min(answered, key=lambda q: q["avg"]) if answered else None
    if strongest and weakest and strongest["avg"] == weakest["avg"]:
        strongest = weakest = None
    return {
        "count": count,
        "avg": round(avg, 2) if avg is not None else None,
        "questions": questions,
        "has_answers": bool(answered),
        "strongest": strongest,
        "weakest": weakest,
        "chart": {"labels": [q["short"] for q in questions],
                  "values": [q["avg"] or 0 for q in questions]},
    }


# ----------------------------------------------------------------------
# Activity calendar (GitHub-style green squares): last 53 weeks, Sunday-first
# ----------------------------------------------------------------------

HEATMAP_WEEKS = 53


def heatmap_start(today=None):
    """First day (a Sunday) of the calendar that ends with today's week."""
    from datetime import date, timedelta
    today = today or date.today()
    this_sunday = today - timedelta(days=(today.weekday() + 1) % 7)
    return this_sunday - timedelta(days=(HEATMAP_WEEKS - 1) * 7)


def build_heatmap(counts, unit=("login", "logins"), today=None):
    """Turn {date: count} into the structure the calendar template draws:
    weeks of 7 day-cells (None after today), month labels, totals.
    Level 0 = nothing that day, 1-4 = from a little to the busiest day."""
    from datetime import date, timedelta
    import math
    today = today or date.today()
    start = heatmap_start(today)
    counts = {d: n for d, n in counts.items() if start <= d <= today}
    busiest = max(counts.values(), default=0)

    weeks, months, prev_month = [], [], None
    for w in range(HEATMAP_WEEKS):
        week_start = start + timedelta(days=w * 7)
        if week_start.month != prev_month:
            months.append((w, week_start.strftime("%b")))
            prev_month = week_start.month
        week = []
        for d in range(7):
            day = week_start + timedelta(days=d)
            if day > today:
                week.append(None)
                continue
            n = counts.get(day, 0)
            level = 0 if n == 0 else min(4, math.ceil(n / busiest * 4))
            label = day.strftime("%a, %d %b %Y")
            word = unit[0] if n == 1 else unit[1]
            week.append({"date": day, "count": n, "level": level,
                         "title": (f"{n} {word} on {label}" if n else f"No {unit[1]} on {label}")})
        weeks.append(week)
    if len(months) > 1 and months[1][0] < 3:
        months = months[1:]          # first label would crowd the next one

    return {"weeks": weeks, "months": months,
            "total": sum(counts.values()), "active_days": len(counts),
            "unit": unit[0] if sum(counts.values()) == 1 else unit[1]}


def get_login_activity(conn, user_id):
    """Login calendar for one person (customer, staff or admin)."""
    counts = User.login_counts(conn, user_id, heatmap_start())
    return build_heatmap(counts, unit=("login", "logins"))


def get_staff_detail(conn, staff_id, days=14):
    """Everything the Admin's per-staff page needs: profile, KPIs, ranking
    vs the team, tier progress, chart datasets, recent work and feedback.
    Returns None if staff_id isn't a Staff member."""
    from datetime import datetime, timedelta

    staff = User.find_by_id(conn, staff_id)
    if not staff or staff.role != "staff":
        return None

    team = calculate_staff_performance(conn)
    me = next((p for p in team if p["staff_id"] == staff_id), None)
    rank = (team.index(me) + 1) if me else None
    rated = [p["avg_rating"] for p in team if p["avg_rating"] is not None]
    team_avg_rating = round(sum(rated) / len(rated), 2) if rated else None
    team_avg_resolved = round(sum(p["resolved_count"] for p in team) / len(team), 1) if team else 0

    cur = conn.cursor(dictionary=True)
    cur.execute(
        """SELECT t.id, t.amount, t.`timestamp`, t.resolved_at, t.risk_score, t.status,
                  sa.account_number AS sender_account, ra.account_number AS receiver_account
           FROM transactions t
           JOIN accounts sa ON sa.id = t.sender_id
           JOIN accounts ra ON ra.id = t.receiver_id
           WHERE t.resolved_by = %s AND t.resolved_at IS NOT NULL
           ORDER BY t.resolved_at DESC""",
        (staff_id,),
    )
    resolved = cur.fetchall()
    cur.close()

    feedback = Feedback.for_staff(conn, staff_id)

    # -- charts -------------------------------------------------------
    today = datetime.now().date()
    day_list = [today - timedelta(days=i) for i in range(days - 1, -1, -1)]
    per_day = {d: 0 for d in day_list}
    buckets = {"Low (0-39)": 0, "Medium (40-69)": 0, "High (70-100)": 0}
    for tx in resolved:
        d = tx["resolved_at"].date()
        if d in per_day:
            per_day[d] += 1
        score = tx["risk_score"]
        key = "High (70-100)" if score >= 70 else "Medium (40-69)" if score >= 40 else "Low (0-39)"
        buckets[key] += 1

    rating_counts = [0, 0, 0, 0, 0]
    for f in feedback:
        rating_counts[int(f["rating"]) - 1] += 1

    week_ago = datetime.now() - timedelta(days=7)
    resolved_last_7 = sum(1 for tx in resolved if tx["resolved_at"] >= week_ago)

    # -- per-question breakdown (from the 10-question feedback form) ----
    q_avgs = Feedback.question_averages_for_staff(conn, staff_id)
    questions = []
    for q in STAFF_QUESTIONS:
        avg, n = q_avgs.get(q["no"], (None, 0))
        questions.append({
            "no": q["no"], "short": q["short"], "text": q["text"],
            "avg": round(avg, 2) if avg is not None else None,
            "count": n,
            "pct": round(avg / 5 * 100) if avg is not None else 0,
        })
    answered = [q for q in questions if q["avg"] is not None]
    strongest = max(answered, key=lambda q: q["avg"]) if answered else None
    weakest = min(answered, key=lambda q: q["avg"]) if answered else None
    if strongest and weakest and strongest["avg"] == weakest["avg"]:
        strongest = weakest = None  # all equal -> nothing to highlight

    from collections import Counter
    resolved_days = Counter(tx["resolved_at"].date() for tx in resolved)
    heat_logins = get_login_activity(conn, staff_id)
    heat_resolved = build_heatmap(dict(resolved_days), unit=("case resolved", "cases resolved"))

    return {
        "heat_logins": heat_logins,
        "heat_resolved": heat_resolved,
        "questions": questions,
        "strongest": strongest,
        "weakest": weakest,
        "staff": staff,
        "perf": me or {"resolved_count": 0, "avg_resolution_minutes": None,
                       "avg_rating": None, "reward_tier": "Unranked", "score": 0},
        "rank": rank,
        "team_size": len(team),
        "team_avg_rating": team_avg_rating,
        "team_avg_resolved": team_avg_resolved,
        "score_info": (me["score_info"] if me else score_breakdown(None, 0, None)),
        "resolved_last_7": resolved_last_7,
        "feedback_count": len(feedback),
        "recent_resolved": resolved[:10],
        "feedback": feedback[:10],
        "charts": {
            "daily": {"labels": [d.strftime("%d %b") for d in day_list],
                      "values": [per_day[d] for d in day_list]},
            "ratings": {"labels": ["1★", "2★", "3★", "4★", "5★"], "values": rating_counts},
            "risk": {"labels": list(buckets.keys()), "values": list(buckets.values())},
            "questions": {"labels": [q["short"] for q in questions],
                          "values": [q["avg"] or 0 for q in questions]},
        },
    }


# ======================================================================
# 3.4 / 4.2 — Feedback
# ======================================================================

def get_feedback_by_staff(conn, staff_id):
    """All feedback customers have left about one staff member."""
    return Feedback.for_staff(conn, staff_id)


def get_global_feedback(conn, min_rating=None, feedback_type=None, start_date=None, end_date=None):
    """All feedback in the bank, for the Admin's global feedback dashboard."""
    return Feedback.all(conn, min_rating=min_rating, feedback_type=feedback_type,
                         start_date=start_date, end_date=end_date)


# ======================================================================
# 3.3 — Staff Dashboard chart datasets (Chart.js consumes these as JSON)
# ======================================================================

def bank_wide_chart_data(conn, days=14):
    """Everything the Staff Dashboard's three charts need, bundled into
    one call so the route only has to make one round trip."""
    daily_totals = Transaction.bank_wide_daily_totals(conn, days=days)
    daily_risk = Transaction.bank_wide_daily_avg_risk(conn, days=days)
    flagged_vs_normal = Transaction.flagged_vs_normal_counts(conn)

    return {
        "transactions_over_time": {
            "labels": [str(r["day"]) for r in daily_totals],
            "totals": [float(r["total"]) for r in daily_totals],
        },
        "risk_score_trend": {
            "labels": [str(r["day"]) for r in daily_risk],
            "avg_scores": [round(float(r["avg_score"]), 1) for r in daily_risk],
        },
        "flagged_vs_normal": flagged_vs_normal,
    }