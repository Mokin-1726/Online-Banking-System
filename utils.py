"""
Small, dependency-light helpers shared across routes.py and models.py.
Kept separate from both so neither has to import the other for basics.
"""

import random
import string
from functools import wraps

import bcrypt
from flask import session, redirect, url_for, flash, request, jsonify


# ----------------------------------------------------------------------
# Password hashing
# ----------------------------------------------------------------------

def hash_password(plaintext: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plaintext.encode("utf-8"), salt).decode("utf-8")


def verify_password(plaintext: str, password_hash: str) -> bool:
    if not password_hash:
        return False
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        # malformed hash stored — never trust an unverifiable password
        return False


# ----------------------------------------------------------------------
# Account numbers
# ----------------------------------------------------------------------

def generate_account_number() -> str:
    """A 12-digit account number, e.g. '482913770156'. Collisions are
    astronomically unlikely at coursework scale; the DB UNIQUE constraint
    is the real safety net."""
    return "".join(random.choices(string.digits, k=12))


# ----------------------------------------------------------------------
# Auth decorators
# ----------------------------------------------------------------------

def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            if request.accept_mimetypes.best == "application/json" or request.is_json:
                return jsonify({"error": "Authentication required"}), 401
            flash("Please log in to continue.", "error")
            return redirect(url_for("routes.login"))
        return view_func(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in to continue.", "error")
                return redirect(url_for("routes.login"))
            if session.get("role") not in allowed_roles:
                if request.is_json:
                    return jsonify({"error": "You don't have permission to do that."}), 403
                flash("You don't have permission to view that page.", "error")
                return redirect(url_for("routes.dashboard"))
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


# ----------------------------------------------------------------------
# Misc formatting
# ----------------------------------------------------------------------

def as_currency(amount) -> str:
    try:
        return f"₹{float(amount):,.2f}"
    except (TypeError, ValueError):
        return "₹0.00"


def humanize_minutes(minutes) -> str:
    """8297.4 -> '5d 18h', 135 -> '2h 15m', 12 -> '12 min'."""
    if minutes is None:
        return "—"
    minutes = float(minutes)
    if minutes < 1:
        return "< 1 min"
    if minutes < 60:
        return f"{minutes:.0f} min"
    hours = minutes / 60
    if hours < 24:
        return f"{int(hours)}h {int(minutes % 60)}m"
    return f"{int(hours // 24)}d {int(hours % 24)}h"


# ----------------------------------------------------------------------
# Phone numbers and UPI IDs
# ----------------------------------------------------------------------

UPI_HANDLE = "ledgerline"


def normalize_phone(raw):
    """Return a clean 10-digit Indian mobile number, or None if invalid.

    Accepts '98765 43210', '+91 98765-43210', '09876543210' etc. A valid
    number is 10 digits starting with 6-9.
    """
    if not raw:
        return None
    digits = "".join(ch for ch in str(raw) if ch.isdigit())
    if len(digits) == 12 and digits.startswith("91"):
        digits = digits[2:]
    elif len(digits) == 11 and digits.startswith("0"):
        digits = digits[1:]
    if len(digits) == 10 and digits[0] in "6789":
        return digits
    return None


def make_upi_id(phone):
    """UPI ID is created from the phone number: 9876543210 -> 9876543210@ledgerline"""
    return f"{phone}@{UPI_HANDLE}"


def normalize_upi(raw):
    return (raw or "").strip().lower()


def email_upi_base(email):
    """Local part of the email, cleaned: Abc.Test@gmail.com -> abc.test
    (letters, digits and . _ - are kept; anything else is dropped)."""
    local = (email or "").strip().lower().split("@")[0]
    cleaned = "".join(ch for ch in local if ch.isalnum() or ch in "._-")
    return cleaned or "user"


def make_email_upi_id(email, suffix=""):
    """abc@gmail.com -> abc@ledgerline. `suffix` ('2', '3', ...) is only added
    when another customer already has that ID (e.g. abc@yahoo.com -> abc2@ledgerline)."""
    return f"{email_upi_base(email)}{suffix}@{UPI_HANDLE}"


def legacy_email_upi_id(email):
    """The earlier format (abc@gmail.com -> abc.gmail.com@ledgerline). Only used
    to recognise and upgrade IDs created before the short format."""
    cleaned = (email or "").strip().lower().replace("@", ".")
    return "".join(ch for ch in cleaned if ch.isalnum() or ch in "._-") + f"@{UPI_HANDLE}"