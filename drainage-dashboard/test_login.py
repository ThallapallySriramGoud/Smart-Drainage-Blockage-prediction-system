"""
test_login.py – Verify operator login fixes using Flask's test client.

Usage:
    python test_login.py

Uses a temporary SQLite database so the real local.db is never touched.
"""

import os
import sys
import tempfile

# ── Configure environment BEFORE importing app ──────────────────────────────
# Create a throwaway database file
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()

# Make sure we are NOT in "Render mode"
os.environ.pop("RENDER", None)
# Point DATABASE_URL at the temp database so app.py uses it at import time
os.environ["DATABASE_URL"] = "sqlite:///" + _tmp.name.replace("\\", "/")
os.environ["SECRET_KEY"] = "test-secret-key-for-testing"
# Clear any admin env vars so the bootstrap code doesn't try to create one
os.environ.pop("ADMIN_USERNAME", None)
os.environ.pop("ADMIN_PASSWORD", None)

from app import app, db, User, Region  # noqa: E402

app.config["TESTING"] = True
app.config["SESSION_COOKIE_SECURE"] = False   # test client uses HTTP


def setup():
    """Create tables and seed test data."""
    with app.app_context():
        db.create_all()

        # Create a region
        region = Region(name="Test Region", code="test-region",
                        device_key="test-device-key-1234")
        db.session.add(region)
        db.session.flush()

        # Create an operator with a known password
        op = User(login_id="north-01", role="operator",
                  region_id=region.id, must_change_password=False)
        op.set_password("correct-password")
        db.session.add(op)

        # Create an operator that must change password
        op2 = User(login_id="change-me", role="operator",
                   region_id=region.id, must_change_password=True)
        op2.set_password("temp-password")
        db.session.add(op2)

        # Create a second operator (to test rate-limit isolation)
        op3 = User(login_id="market-01", role="operator",
                   region_id=region.id, must_change_password=False)
        op3.set_password("market-password")
        db.session.add(op3)

        # Create an admin
        adm = User(login_id="admin", role="admin",
                   region_id=None, must_change_password=False)
        adm.set_password("admin-password")
        db.session.add(adm)

        db.session.commit()


def _get_csrf(client):
    """GET /login and extract the csrf_token from the hidden field."""
    rv = client.get("/login")
    html = rv.data.decode()
    marker = 'name="csrf_token" value="'
    idx = html.index(marker) + len(marker)
    end = html.index('"', idx)
    return html[idx:end]


def _login(client, login_id, password, role="operator", csrf=None):
    """POST to /login with the given credentials."""
    if csrf is None:
        csrf = _get_csrf(client)
    return client.post("/login", data={
        "login_id": login_id,
        "password": password,
        "role": role,
        "csrf_token": csrf,
    }, follow_redirects=False)


passed = 0
failed = 0


def check(name, condition):
    global passed, failed
    if condition:
        print("  PASS  {}".format(name))
        passed += 1
    else:
        print("  FAIL  {}".format(name))
        failed += 1


def test_correct_login():
    """Operator logs in with correct credentials."""
    with app.test_client() as c:
        rv = _login(c, "north-01", "correct-password", "operator")
        check("correct login -> redirect", rv.status_code in (302, 303))
        loc = rv.headers.get("Location", "")
        check("correct login -> redirects to /",
              loc.endswith("/") or loc == "/")


def test_case_insensitive_login():
    """Operator logs in with different capitalisation of login_id."""
    with app.test_client() as c:
        rv = _login(c, "North-01", "correct-password", "operator")
        check("case-insensitive login -> redirect", rv.status_code in (302, 303))

    with app.test_client() as c:
        rv = _login(c, "NORTH-01", "correct-password", "operator")
        check("all-caps login -> redirect", rv.status_code in (302, 303))


def test_wrong_password():
    """Wrong password shows the error."""
    with app.test_client() as c:
        rv = _login(c, "north-01", "wrong-password", "operator")
        check("wrong password -> 200 (re-render form)", rv.status_code == 200)
        check("wrong password -> error message",
              b"User not found or incorrect password" in rv.data)


def test_wrong_role_toggle():
    """Operator with the 'Admin' toggle selected is rejected."""
    with app.test_client() as c:
        rv = _login(c, "north-01", "correct-password", "admin")
        check("operator + admin toggle -> 200", rv.status_code == 200)
        check("operator + admin toggle -> error message",
              b"User not found or incorrect password" in rv.data)


def test_must_change_password_redirect():
    """must_change_password operator is redirected to /change-password."""
    with app.test_client() as c:
        rv = _login(c, "change-me", "temp-password", "operator")
        check("must_change -> redirect", rv.status_code in (302, 303))
        # The redirect goes to / first, then login_required redirects to
        # /change-password.
        loc = rv.headers.get("Location", "")
        rv2 = c.get(loc, follow_redirects=False)
        loc2 = rv2.headers.get("Location", "")
        check("must_change -> ends at /change-password",
              "/change-password" in loc2 or "/change-password" in loc)


def test_rate_limiting():
    """5 bad attempts then a block, and a different operator is NOT blocked."""
    from app import _bad_attempts
    _bad_attempts.clear()

    with app.test_client() as c:
        for i in range(5):
            _login(c, "north-01", "wrong-{}".format(i), "operator")

        # 6th attempt should be blocked
        rv = _login(c, "north-01", "correct-password", "operator")
        check("6th attempt -> blocked (200)", rv.status_code == 200)
        check("6th attempt -> block message",
              b"Too many failed attempts" in rv.data)

    # A different operator from the same test client should NOT be blocked
    with app.test_client() as c:
        rv = _login(c, "market-01", "market-password", "operator")
        check("different operator -> NOT blocked", rv.status_code in (302, 303))


def test_missing_csrf():
    """Missing CSRF token is rejected."""
    with app.test_client() as c:
        rv = c.post("/login", data={
            "login_id": "north-01",
            "password": "correct-password",
            "role": "operator",
            "csrf_token": "bad-token",
        })
        check("missing CSRF -> 200", rv.status_code == 200)
        check("missing CSRF -> error message",
              b"Session expired or cookies are disabled" in rv.data)


def test_must_change_full_flow():
    """Full flow: login -> /change-password -> change password -> dashboard."""
    with app.test_client() as c:
        # Login
        rv = _login(c, "change-me", "temp-password", "operator")
        assert rv.status_code in (302, 303)
        # Follow to /
        rv2 = c.get(rv.headers["Location"], follow_redirects=False)
        loc2 = rv2.headers.get("Location", "")
        check("full flow -> redirected to /change-password",
              "/change-password" in loc2)

        # GET the change-password page
        rv3 = c.get("/change-password")
        check("full flow -> change password page loads", rv3.status_code == 200)

        # Extract CSRF token
        html = rv3.data.decode()
        marker = 'name="csrf_token" value="'
        idx = html.index(marker) + len(marker)
        end = html.index('"', idx)
        csrf = html[idx:end]

        # POST new password
        rv4 = c.post("/change-password", data={
            "csrf_token": csrf,
            "current_password": "temp-password",
            "new_password": "new-secure-pw-123",
            "confirm_password": "new-secure-pw-123",
        }, follow_redirects=False)
        check("full flow -> password changed -> redirect",
              rv4.status_code in (302, 303))
        loc4 = rv4.headers.get("Location", "")
        check("full flow -> redirects to /",
              loc4.endswith("/") or loc4 == "/")

        # Follow to / — should render dashboard, not redirect again
        rv5 = c.get("/", follow_redirects=False)
        check("full flow -> dashboard loads (not redirect loop)",
              rv5.status_code == 200)


if __name__ == "__main__":
    setup()
    print()
    print("=" * 60)
    print("  Operator Login Tests")
    print("=" * 60)
    print()

    test_correct_login()
    print()
    test_case_insensitive_login()
    print()
    test_wrong_password()
    print()
    test_wrong_role_toggle()
    print()
    test_must_change_password_redirect()
    print()
    test_rate_limiting()
    print()
    test_missing_csrf()
    print()
    test_must_change_full_flow()
    print()

    print("=" * 60)
    print("  Results: {} passed, {} failed".format(passed, failed))
    print("=" * 60)

    # Cleanup
    try:
        os.unlink(_tmp.name)
    except OSError:
        pass

    sys.exit(0 if failed == 0 else 1)
