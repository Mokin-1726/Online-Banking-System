"""
Seed test accounts for Ledgerline.

Run this from inside your banking_system folder (same place as app.py),
after your MySQL server is running and app.py has been started at
least once (so the database/tables exist):

    python seed_test_users.py

Creates one Admin and one Customer with known passwords, printing the
credentials at the end. Safe to run more than once — it skips
creating an Admin if one already exists, and skips the Customer if
that email is already registered.
"""

from app import get_db_connection
from models import Admin, Customer, User

TEST_ADMIN = {
    "name": "Test Admin",
    "email": "admin@ledgerline.test",
    "password": "Admin@12345",
}

TEST_CUSTOMER = {
    "name": "Test Customer",
    "email": "customer@ledgerline.test",
    "password": "Customer@123",
}


def seed():
    conn = get_db_connection()
    try:
        if User.admin_exists(conn):
            print(f"[skip] An Admin already exists — not creating a new one.")
        else:
            Admin.bootstrap(conn, TEST_ADMIN["name"], TEST_ADMIN["email"], TEST_ADMIN["password"])
            print(f"[created] Admin -> {TEST_ADMIN['email']}")

        if User.find_by_email(conn, TEST_CUSTOMER["email"]):
            print(f"[skip] Customer {TEST_CUSTOMER['email']} already exists.")
        else:
            Customer.register(conn, TEST_CUSTOMER["name"], TEST_CUSTOMER["email"], TEST_CUSTOMER["password"])
            print(f"[created] Customer -> {TEST_CUSTOMER['email']}")
    finally:
        conn.close()

    print("\n--- Test login credentials ---")
    print(f"Admin:    {TEST_ADMIN['email']}  /  {TEST_ADMIN['password']}")
    print(f"Customer: {TEST_CUSTOMER['email']}  /  {TEST_CUSTOMER['password']}")
    print("Log in at http://localhost:5000/login")


if __name__ == "__main__":
    seed()
