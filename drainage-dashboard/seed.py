"""
seed.py – Create tables and populate sample regions / operators.

Edit REGIONS below to add, rename or remove entries before running.

Usage:
    python seed.py

The script is idempotent: it skips anything that already exists and
only prints newly created keys and passwords.
"""

import os
import secrets

# ── Edit this list to change the seed data ───────────────────────────────────
REGIONS = [
    {"name": "Ward 1 - North Zone",   "code": "ward-1-north",  "operator": "north-01"},
    {"name": "Ward 2 - Market Area",  "code": "ward-2-market", "operator": "market-01"},
    {"name": "Ward 3 - Campus Road",  "code": "ward-3-campus", "operator": "campus-01"},
]
# ─────────────────────────────────────────────────────────────────────────────

# Import the Flask app so SQLAlchemy is fully configured before we touch the DB
from app import app, db, Region, User   # noqa: E402


def run():
    with app.app_context():
        db.create_all()

        for entry in REGIONS:
            # ── Region ──────────────────────────────────────────────────────
            region = Region.query.filter_by(code=entry["code"]).first()
            if region is None:
                device_key = secrets.token_urlsafe(32)
                region = Region(
                    name=entry["name"],
                    code=entry["code"],
                    device_key=device_key,
                )
                db.session.add(region)
                db.session.flush()   # get the id before creating the user
                print("Created region: {} [code={}]".format(
                    entry["name"], entry["code"]))
                print("  Device key : {}".format(device_key))
            else:
                print("Region '{}' already exists, skipping.".format(
                    entry["code"]))

            # ── Operator ────────────────────────────────────────────────────
            login_id = entry["operator"]
            user = User.query.filter_by(login_id=login_id).first()
            if user is None:
                tmp_password = secrets.token_urlsafe(10)
                user = User(
                    login_id=login_id,
                    role="operator",
                    region_id=region.id,
                    must_change_password=True,
                )
                user.set_password(tmp_password)
                db.session.add(user)
                print("  Created operator: {} — temporary password: {}".format(
                    login_id, tmp_password))
            else:
                print("  Operator '{}' already exists, skipping.".format(login_id))

        db.session.commit()
        print("\nDone.")


if __name__ == "__main__":
    run()
