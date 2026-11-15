"""
Smart Drainage Monitoring System – Flask Backend (Phase 1)

What changed in Phase 1
------------------------
* SQLite + raw sqlite3  →  Flask-SQLAlchemy (supports PostgreSQL on Render)
* DATABASE_URL read from environment; "postgres://" → "postgresql://"
* Region / User models added; every data row carries a region_id
* /api/data and /api/material identify the region via X-API-Key → Region.device_key
* Login (/login), change-password (/change-password), admin (/admin) added
* "/", /api/latest, /api/history, /api/alerts require a logged-in session
* Rate-limiting (5 bad attempts → 5-minute block) for login
* ProxyFix so HTTPS detection works behind Render's load-balancer
* SECRET_KEY / ADMIN_* / DATABASE_URL validated at startup on Render

The blockage/analysis/material detection logic is UNCHANGED from the original.
"""

import hmac
import os
import secrets
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from functools import wraps

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

from playbook import get_plan

# ─────────────────────────────────────────────────────────────────────────────
# App setup
# ─────────────────────────────────────────────────────────────────────────────

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ── Secrets and database URL ────────────────────────────────────────────────
ON_RENDER = bool(os.environ.get("RENDER"))

_raw_db_url = os.environ.get("DATABASE_URL", "")
# Heroku/Render sometimes give "postgres://" which SQLAlchemy 1.4+ rejects
if _raw_db_url.startswith("postgres://"):
    _raw_db_url = "postgresql://" + _raw_db_url[len("postgres://"):]
# Force the psycopg2 driver so it works with every SQLAlchemy version
if _raw_db_url.startswith("postgresql://"):
    _raw_db_url = "postgresql+psycopg2://" + _raw_db_url[len("postgresql://"):]
DATABASE_URL = _raw_db_url or "sqlite:///local.db"

SECRET_KEY = os.environ.get("SECRET_KEY", "")

if ON_RENDER:
    missing = []
    if not SECRET_KEY:
        missing.append("SECRET_KEY")
    if not _raw_db_url:
        missing.append("DATABASE_URL")
    if missing:
        sys.exit(
            "ERROR: Running on Render but required environment "
            "variable(s) are not set: {}".format(", ".join(missing))
        )
else:
    if not SECRET_KEY:
        SECRET_KEY = "dev-only-secret-key-do-not-use-in-production"
        print(
            "WARNING: SECRET_KEY is not set. "
            "Using an insecure development key. "
            "Set SECRET_KEY in your environment before deploying."
        )

app.config["SECRET_KEY"] = SECRET_KEY
app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_pre_ping": True,
    "pool_recycle": 300,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Session cookie settings
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = ON_RENDER   # Secure only on HTTPS
app.config["PERMANENT_SESSION_LIFETIME"] = 8 * 3600  # 8 hours

db = SQLAlchemy(app)

# ─────────────────────────────────────────────────────────────────────────────
# Detection config (unchanged)
# ─────────────────────────────────────────────────────────────────────────────

CFG = {
    "CHANNEL_CM":       15,
    "OVERFLOW_CM":      12,
    "GRADIENT_CM":       2.0,
    "RISE_CM_PER_MIN":   0.5,
    "NORMAL_FLOW_LPM":   4.0,
    "FLOW_DROP_RATIO":   0.6,
    "MIN_DEPTH_CM":      1.0,
    "WINDOW":            15,
    "MIN_READINGS":      8,
    "OFFLINE_AFTER_S":   30,
}

# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────

class Region(db.Model):
    __tablename__ = "regions"
    id         = db.Column(db.Integer, primary_key=True)
    name       = db.Column(db.String(120), nullable=False)
    code       = db.Column(db.String(40),  nullable=False, unique=True)
    device_key = db.Column(db.String(64),  nullable=False, unique=True)

    readings  = db.relationship("Reading",  back_populates="region",
                                lazy="dynamic", cascade="all, delete-orphan")
    materials = db.relationship("Material", back_populates="region",
                                lazy="dynamic", cascade="all, delete-orphan")
    alerts    = db.relationship("Alert",    back_populates="region",
                                lazy="dynamic", cascade="all, delete-orphan")
    users     = db.relationship("User",     back_populates="region",
                                lazy="dynamic")


class User(db.Model):
    __tablename__ = "users"
    id                  = db.Column(db.Integer, primary_key=True)
    login_id            = db.Column(db.String(80), nullable=False, unique=True)
    password_hash       = db.Column(db.String(256), nullable=False)
    role                = db.Column(db.String(20),  nullable=False,
                                    default="operator")  # "admin" or "operator"
    region_id           = db.Column(db.Integer, db.ForeignKey("regions.id"),
                                    nullable=True)       # None for admin
    must_change_password = db.Column(db.Boolean, nullable=False, default=False)
    created_at          = db.Column(db.DateTime(timezone=True),
                                    default=lambda: datetime.now(timezone.utc))
    last_login_at       = db.Column(db.DateTime(timezone=True), nullable=True)

    region = db.relationship("Region", back_populates="users")

    def set_password(self, plaintext):
        self.password_hash = generate_password_hash(plaintext)

    def check_password(self, plaintext):
        return check_password_hash(self.password_hash, plaintext)


class Reading(db.Model):
    __tablename__ = "readings"
    id        = db.Column(db.Integer, primary_key=True)
    region_id = db.Column(db.Integer, db.ForeignKey("regions.id"),
                          nullable=False, index=True)
    ts        = db.Column(db.Float,   nullable=False)
    depth_a   = db.Column(db.Float,   nullable=False)
    depth_b   = db.Column(db.Float,   nullable=False)
    depth_c   = db.Column(db.Float,   nullable=False)
    flow      = db.Column(db.Float,   nullable=False)
    temp      = db.Column(db.Float,   nullable=False)
    status    = db.Column(db.String(20), nullable=False)
    location  = db.Column(db.String(20), nullable=False, default="")

    region = db.relationship("Region", back_populates="readings")


class Material(db.Model):
    __tablename__ = "materials"
    id          = db.Column(db.Integer, primary_key=True)
    region_id   = db.Column(db.Integer, db.ForeignKey("regions.id"),
                            nullable=False, index=True)
    ts          = db.Column(db.Float,   nullable=False)
    material    = db.Column(db.String(20), nullable=False)
    confidence  = db.Column(db.Float,   nullable=False)
    ir_detected = db.Column(db.Boolean, nullable=False, default=False)

    region = db.relationship("Region", back_populates="materials")


class Alert(db.Model):
    __tablename__ = "alerts"
    id        = db.Column(db.Integer, primary_key=True)
    region_id = db.Column(db.Integer, db.ForeignKey("regions.id"),
                          nullable=False, index=True)
    ts        = db.Column(db.Float,   nullable=False)
    status    = db.Column(db.String(20), nullable=False)
    location  = db.Column(db.String(20), nullable=False, default="")
    message   = db.Column(db.Text,    nullable=False)

    region = db.relationship("Region", back_populates="alerts")


# ── Incident ──────────────────────────────────────────────────────────────────

class Incident(db.Model):
    """
    Tracks a blockage event from first detection to clearance.

    sensor_state  : "ACTIVE" while sensors still show blockage;
                    "CLEARED" once five consecutive NORMAL readings arrive.
    status        : workflow state (Phase 3 will add transitions; default
                    "DETECTED" for now and nothing changes it in Phase 2).
    normal_streak : counts consecutive NORMAL readings; resets on any
                    non-NORMAL reading; at 5 the incident is CLEARED.
    """
    __tablename__ = "incidents"

    id                  = db.Column(db.Integer, primary_key=True)
    region_id           = db.Column(db.Integer,
                                    db.ForeignKey("regions.id"),
                                    nullable=False, index=True)
    # Channel segment, e.g. "B-C", "A-B", "after C"
    location            = db.Column(db.String(20),  nullable=False)
    # Worst status reached during this incident
    severity            = db.Column(db.String(20),  nullable=False)   # BLOCKAGE | CRITICAL
    confirmed           = db.Column(db.Boolean,     nullable=False, default=False)
    # Identified obstruction
    material            = db.Column(db.String(40),  nullable=False,
                                    default="Not identified")
    material_confidence = db.Column(db.Float,       nullable=True)
    # Workflow status (Phase 3 will add more transitions)
    status              = db.Column(db.String(30),  nullable=False, default="DETECTED")
    # Sensor lifecycle
    sensor_state        = db.Column(db.String(20),  nullable=False, default="ACTIVE")
    normal_streak       = db.Column(db.Integer,     nullable=False, default=0)
    # Timestamps (UTC Unix floats, consistent with every other table)
    detected_at         = db.Column(db.Float,       nullable=False)
    cleared_at          = db.Column(db.Float,       nullable=True)
    # Sensor extremes since the incident opened
    peak_depth_b        = db.Column(db.Float,       nullable=True)
    min_flow            = db.Column(db.Float,       nullable=True)
    # JSON text – last 10 readings at detection
    snapshot            = db.Column(db.Text,        nullable=True)
    # JSON text – playbook plan at opening (or most recent update)
    plan                = db.Column(db.Text,        nullable=True)
    plan_updated_at     = db.Column(db.Float,       nullable=True)

    region = db.relationship("Region")

# ─────────────────────────────────────────────────────────────────────────────
# Detection logic (unchanged from original)
# ─────────────────────────────────────────────────────────────────────────────

def _smooth(rows, key):
    """Average of the last 3 readings for the given column."""
    recent = rows[-3:]
    return sum(r[key] for r in recent) / len(recent)


def _slope(rows, key):
    """Least-squares slope (units/minute), timestamps centred to avoid FP loss."""
    xs = [r["ts"] / 60.0 for r in rows]
    ys = [r[key] for r in rows]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    dx = [x - mean_x for x in xs]
    dy = [y - mean_y for y in ys]
    num = sum(a * b for a, b in zip(dx, dy))
    den = sum(a * a for a in dx)
    if den == 0:
        return 0.0
    return num / den


def analyse(rows):
    """
    Analyse the most recent readings and decide the channel status.

    Parameters
    ----------
    rows : list of dicts (oldest first) with keys ts, depth_a, depth_b,
           depth_c, flow.

    Returns a dict: status, location, score, confirmed, reasons, eta_min,
    slopes.
    """
    if len(rows) < CFG["MIN_READINGS"]:
        return {
            "status": "NORMAL", "location": "", "score": 0,
            "confirmed": False, "reasons": [], "eta_min": None, "slopes": {},
        }

    s_a    = _smooth(rows, "depth_a")
    s_b    = _smooth(rows, "depth_b")
    s_c    = _smooth(rows, "depth_c")
    s_flow = _smooth(rows, "flow")

    slope_a    = _slope(rows, "depth_a")
    slope_b    = _slope(rows, "depth_b")
    slope_c    = _slope(rows, "depth_c")
    slope_flow = _slope(rows, "flow")
    slopes = {
        "depth_a": round(slope_a, 3), "depth_b": round(slope_b, 3),
        "depth_c": round(slope_c, 3), "flow":    round(slope_flow, 3),
    }

    flow_low = (s_flow < CFG["NORMAL_FLOW_LPM"] * CFG["FLOW_DROP_RATIO"]
                and s_a > CFG["MIN_DEPTH_CM"])
    flow_reason = "Flow low ({:.1f} L/min)".format(s_flow)

    seg_ab = {"score": 0, "reasons": [], "diff": s_a - s_b,
              "has_gradient": False, "has_flow_low": False}
    seg_bc = {"score": 0, "reasons": [], "diff": s_b - s_c,
              "has_gradient": False, "has_flow_low": False}
    seg_ac = {"score": 0, "reasons": [], "diff": 0,
              "has_gradient": False, "has_flow_low": False}

    if (s_a - s_b) >= CFG["GRADIENT_CM"]:
        seg_ab["score"] += 2; seg_ab["has_gradient"] = True
        seg_ab["reasons"].append(
            "Water is {:.1f} cm deeper at A than at B".format(s_a - s_b))
    if slope_a >= CFG["RISE_CM_PER_MIN"]:
        seg_ab["score"] += 1
        seg_ab["reasons"].append("Level at A rising {:.1f} cm/min".format(slope_a))
    if flow_low:
        seg_ab["score"] += 1; seg_ab["has_flow_low"] = True
        seg_ab["reasons"].append(flow_reason)

    if (s_b - s_c) >= CFG["GRADIENT_CM"]:
        seg_bc["score"] += 2; seg_bc["has_gradient"] = True
        seg_bc["reasons"].append(
            "Water is {:.1f} cm deeper at B than at C".format(s_b - s_c))
    if slope_b >= CFG["RISE_CM_PER_MIN"]:
        seg_bc["score"] += 1
        seg_bc["reasons"].append("Level at B rising {:.1f} cm/min".format(slope_b))
    if flow_low:
        seg_bc["score"] += 1; seg_bc["has_flow_low"] = True
        seg_bc["reasons"].append(flow_reason)

    if (slope_a >= CFG["RISE_CM_PER_MIN"]
            and slope_b >= CFG["RISE_CM_PER_MIN"]
            and slope_c >= CFG["RISE_CM_PER_MIN"]):
        seg_ac["score"] += 2; seg_ac["has_gradient"] = True
        seg_ac["reasons"].append("All depths rising rapidly")
    if flow_low:
        seg_ac["score"] += 1; seg_ac["has_flow_low"] = True
        seg_ac["reasons"].append(flow_reason)

    segments = [("A-B", seg_ab), ("B-C", seg_bc), ("after C", seg_ac)]
    best_loc, best = max(segments, key=lambda kv: (kv[1]["score"], kv[1]["diff"]))

    if best["score"] >= 3:
        status = "BLOCKAGE"
    elif best["score"] == 2:
        status = "WARNING"
    else:
        status = "NORMAL"

    location = best_loc if status in ("BLOCKAGE", "WARNING") else ""
    reasons  = best["reasons"] if status in ("BLOCKAGE", "WARNING") else []

    max_depth = max(s_a, s_b, s_c)
    if max_depth >= CFG["OVERFLOW_CM"]:
        status = "CRITICAL"
        reasons = list(reasons)
        reasons.append(
            "Water depth {:.1f} cm is at or above the overflow level "
            "({:.0f} cm)".format(max_depth, CFG["OVERFLOW_CM"]))

    eta_min = None
    for depth, slope in [(s_a, slope_a), (s_b, slope_b), (s_c, slope_c)]:
        if slope > 0.1 and depth < CFG["OVERFLOW_CM"]:
            t = (CFG["OVERFLOW_CM"] - depth) / slope
            if eta_min is None or t < eta_min:
                eta_min = t
    if eta_min is not None:
        eta_min = round(eta_min, 1)

    confirmed = (status in ("BLOCKAGE", "CRITICAL")
                 and best["has_gradient"] and best["has_flow_low"])

    return {
        "status": status, "location": location, "score": best["score"],
        "confirmed": confirmed, "reasons": reasons,
        "eta_min": eta_min, "slopes": slopes,
    }

# ─────────────────────────────────────────────────────────────────────────────
# Material helpers (unchanged logic, now query via SQLAlchemy)
# ─────────────────────────────────────────────────────────────────────────────

MATERIALS = ("ROCK", "GRAVEL", "SAND", "PLASTIC", "RUBBER", "WOOD", "OTHER", "UNKNOWN")
CONFIDENCE_THRESHOLD = 0.6
CAUSE_WINDOW_S = 120

BLOCKAGE_ADVICE = {
    "PLASTIC":  "Remove manually, do not flush",
    "RUBBER":   "Remove manually",
    "ROCK":     "Remove with tools",
    "GRAVEL":   "Flush or desilt the channel",
    "SAND":     "Flush or desilt the channel",
    "WOOD":     "Remove debris",
    "OTHER":    "Inspect the channel",
    "UNKNOWN":  "Inspect the channel",
}


def _latest_material(region_id):
    """Return the most recent material detection dict for a region, or None."""
    mat = (Material.query
           .filter_by(region_id=region_id)
           .order_by(Material.id.desc())
           .first())
    if not mat:
        return None
    return {
        "ts": mat.ts,
        "material": mat.material,
        "confidence": mat.confidence,
        "ir_detected": mat.ir_detected,
    }


def _blockage_cause(region_id):
    """Return the best recent material reading as the blockage cause dict."""
    cutoff = time.time() - CAUSE_WINDOW_S
    row = (Material.query
           .filter(
               Material.region_id == region_id,
               Material.ts >= cutoff,
               Material.confidence >= CONFIDENCE_THRESHOLD,
               Material.material != "UNKNOWN",
           )
           .order_by(Material.id.desc())
           .first())
    if row:
        return {
            "material":   row.material,
            "confidence": round(row.confidence, 2),
            "advice":     BLOCKAGE_ADVICE.get(row.material, BLOCKAGE_ADVICE["OTHER"]),
        }
    return {
        "material":   "Not identified",
        "confidence": None,
        "advice":     BLOCKAGE_ADVICE["OTHER"],
    }

# ─────────────────────────────────────────────────────────────────────────────
# Incident engine
# ─────────────────────────────────────────────────────────────────────────────

# Severity ordering – higher index = worse.
_SEV_ORDER = ["WARNING", "BLOCKAGE", "CRITICAL"]


def _active_incident_dict(region_id):
    """Return the active Incident for a region as a dict, or None."""
    inc = (Incident.query
           .filter_by(region_id=region_id, sensor_state="ACTIVE")
           .first())
    if inc is None:
        return None
    return _incident_dict(inc)


def _incident_dict(inc):
    """Serialise an Incident row to a plain dict for API responses."""
    import json as _json
    plan_obj = None
    try:
        if inc.plan:
            plan_obj = _json.loads(inc.plan)
    except Exception:
        pass
    return {
        "id":           inc.id,
        "status":       inc.status,
        "severity":     inc.severity,
        "confirmed":    inc.confirmed,
        "location":     inc.location,
        "material":     inc.material,
        "confidence":   inc.material_confidence,
        "sensor_state": inc.sensor_state,
        "detected_at":  inc.detected_at,
        "cleared_at":   inc.cleared_at,
        "plan":         plan_obj,
    }


def _refresh_plan(inc):
    """Regenerate and store the playbook plan for an incident."""
    import json as _json
    plan_obj = get_plan(inc.material, inc.severity, inc.location)
    inc.plan            = _json.dumps(plan_obj)
    inc.plan_updated_at = time.time()


def update_incident(region, analysis, reading):
    """
    Update incident records for a region after each sensor reading.

    Rules
    -----
    * BLOCKAGE or CRITICAL with no ACTIVE incident at this location
      → open a new Incident, snapshot the last 10 readings, generate a plan,
        log an alert.
    * ACTIVE incident at this location:
      → raise severity if status is worse (never downgrade);
        update peak_depth_b and min_flow;
        reset normal_streak when status is not NORMAL.
    * NORMAL reading and an ACTIVE incident:
      → increment normal_streak; at 5 clear the incident.

    Uses only the database – no module-level state – so it is safe with
    multiple gunicorn workers.
    """
    import json as _json

    status   = analysis["status"]
    location = analysis["location"]
    now      = time.time()

    # Only the blockage statuses matter here.
    is_blockage = status in ("BLOCKAGE", "CRITICAL")
    is_warning  = status == "WARNING"
    is_normal   = status == "NORMAL"

    # ── Find the ACTIVE incident for this region+location (if any) ──────────
    active_location = location if location else None

    active = None
    if active_location:
        active = (Incident.query
                  .filter_by(region_id=region.id,
                             location=active_location,
                             sensor_state="ACTIVE")
                  .first())

    # Also look for any ACTIVE incident for this region (needed for the
    # normal-streak logic when location becomes "").
    any_active = (Incident.query
                  .filter_by(region_id=region.id, sensor_state="ACTIVE")
                  .first())

    # ── Case 1: Blockage with no active incident at this location ────────────
    if is_blockage and active is None:
        # Fetch the last 10 readings for the snapshot.
        last_rows = (Reading.query
                     .filter_by(region_id=region.id)
                     .order_by(Reading.id.desc())
                     .limit(10)
                     .all())
        snapshot_data = [
            {"ts": r.ts, "depth_a": r.depth_a, "depth_b": r.depth_b,
             "depth_c": r.depth_c, "flow": r.flow, "temp": r.temp}
            for r in reversed(last_rows)
        ]

        # Identify the best available material for this incident.
        cause = _blockage_cause(region.id)
        mat   = cause["material"]
        conf  = cause["confidence"]

        inc = Incident(
            region_id=region.id,
            location=location,
            severity=status,
            confirmed=analysis["confirmed"],
            material=mat,
            material_confidence=conf,
            sensor_state="ACTIVE",
            normal_streak=0,
            detected_at=now,
            peak_depth_b=reading.get("depth_b"),
            min_flow=reading.get("flow"),
            snapshot=_json.dumps(snapshot_data),
        )
        # Generate initial plan.
        _refresh_plan(inc)

        db.session.add(inc)
        db.session.flush()   # populate inc.id before writing the alert

        db.session.add(Alert(
            region_id=region.id,
            ts=now,
            status="BLOCKAGE",
            location=location,
            message="Incident #{} opened ({})".format(inc.id, location),
        ))

    # ── Case 2: Blockage with an existing active incident ───────────────────
    elif is_blockage and active is not None:
        # Raise severity if the status got worse; never lower it.
        try:
            if _SEV_ORDER.index(status) > _SEV_ORDER.index(active.severity):
                active.severity = status
                _refresh_plan(active)
        except ValueError:
            pass   # status not in _SEV_ORDER – ignore

        # Always update confirmed if newly confirmed.
        if analysis["confirmed"] and not active.confirmed:
            active.confirmed = True

        # Update extremes.
        depth_b = reading.get("depth_b")
        flow    = reading.get("flow")
        if depth_b is not None:
            if active.peak_depth_b is None or depth_b > active.peak_depth_b:
                active.peak_depth_b = depth_b
        if flow is not None:
            if active.min_flow is None or flow < active.min_flow:
                active.min_flow = flow

        # Non-normal reading resets the clearance streak.
        active.normal_streak = 0

    # ── Case 3: Normal reading — advance the clearance streak ───────────────
    if is_normal and any_active is not None:
        any_active.normal_streak += 1
        if any_active.normal_streak >= 5:
            any_active.sensor_state = "CLEARED"
            any_active.cleared_at   = now
            db.session.add(Alert(
                region_id=region.id,
                ts=now,
                status="NORMAL",
                location=any_active.location,
                message="Incident #{}: sensors back to normal".format(any_active.id),
            ))

# ─────────────────────────────────────────────────────────────────────────────
# Rate-limiting helpers (in-memory, fine for one or two workers)
# ─────────────────────────────────────────────────────────────────────────────

# {key: [timestamp, ...]}  key is "ip:<ip>" or "id:<login_id>"
_bad_attempts = defaultdict(list)
_BLOCK_WINDOW = 300          # 5 minutes
_MAX_ATTEMPTS = 5


def _is_blocked(key):
    now = time.time()
    attempts = [t for t in _bad_attempts[key] if now - t < _BLOCK_WINDOW]
    _bad_attempts[key] = attempts
    return len(attempts) >= _MAX_ATTEMPTS


def _record_failure(key):
    _bad_attempts[key].append(time.time())


def _clear_failures(key):
    _bad_attempts.pop(key, None)

# ─────────────────────────────────────────────────────────────────────────────
# CSRF helpers
# ─────────────────────────────────────────────────────────────────────────────

def _csrf_token():
    """Return a per-session CSRF token, generating one if needed."""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def _csrf_ok():
    """Check that the submitted form CSRF token matches the session token."""
    token = session.get("csrf_token", "")
    submitted = request.form.get("csrf_token", "")
    if not token or not submitted:
        return False
    return hmac.compare_digest(token, submitted)

# ─────────────────────────────────────────────────────────────────────────────
# Auth helpers / decorators
# ─────────────────────────────────────────────────────────────────────────────

def _current_user():
    """Return the User object for the logged-in session, or None."""
    uid = session.get("user_id")
    if uid is None:
        return None
    return db.session.get(User, uid)


def _region_for_session(user):
    """
    Return the Region the user should see.
    - Operator: their fixed region.
    - Admin: the region they chose at /admin (stored in session), or None.
    """
    if user.role == "operator":
        return user.region
    # Admin
    rid = session.get("admin_region_id")
    if rid:
        return db.session.get(Region, rid)
    return None


def login_required(f):
    """Redirect page requests to /login; return 401 JSON for API requests."""
    @wraps(f)
    def decorated(*args, **kwargs):
        user = _current_user()
        if user is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("login", next=request.path))
        # Force password change before anything else
        if user.must_change_password and request.endpoint != "change_password":
            if request.path.startswith("/api/"):
                return jsonify({"error": "password change required"}), 403
            return redirect(url_for("change_password"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    """Requires admin role on top of login_required."""
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        user = _current_user()
        if user.role != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"error": "forbidden"}), 403
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return decorated

# ─────────────────────────────────────────────────────────────────────────────
# Device API — no login, region identified by X-API-Key
# ─────────────────────────────────────────────────────────────────────────────

def _region_from_key():
    """Return the Region matching the X-API-Key header, or None."""
    key = request.headers.get("X-API-Key", "")
    if not key:
        return None
    return Region.query.filter_by(device_key=key).first()


@app.route("/api/data", methods=["POST"])
def api_data():
    """Receive a sensor reading from the ESP32 / simulator."""
    region = _region_from_key()
    if region is None:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid or empty JSON body"}), 400

    fields = ["depth_a", "depth_b", "depth_c", "flow", "temp"]
    reading = {}
    for f in fields:
        val = data.get(f)
        if val is None:
            return jsonify({"error": "missing field: {}".format(f)}), 400
        if isinstance(val, bool):
            return jsonify({"error": "{} is not a number".format(f)}), 400
        try:
            reading[f] = float(val)
        except (TypeError, ValueError):
            return jsonify({"error": "{} is not a number".format(f)}), 400

    now = time.time()

    # Fetch the last WINDOW-1 readings for this region, oldest first
    prev_rows = (Reading.query
                 .filter_by(region_id=region.id)
                 .order_by(Reading.id.desc())
                 .limit(CFG["WINDOW"] - 1)
                 .all())
    rows = [
        {"ts": r.ts, "depth_a": r.depth_a, "depth_b": r.depth_b,
         "depth_c": r.depth_c, "flow": r.flow}
        for r in reversed(prev_rows)
    ]
    rows.append({
        "ts": now,
        "depth_a": reading["depth_a"], "depth_b": reading["depth_b"],
        "depth_c": reading["depth_c"], "flow": reading["flow"],
    })

    result = analyse(rows)

    # Previous status for change detection
    prev = (Reading.query
            .filter_by(region_id=region.id)
            .order_by(Reading.id.desc())
            .first())

    # Persist the new reading
    new_reading = Reading(
        region_id=region.id, ts=now,
        depth_a=reading["depth_a"], depth_b=reading["depth_b"],
        depth_c=reading["depth_c"], flow=reading["flow"], temp=reading["temp"],
        status=result["status"], location=result["location"],
    )
    db.session.add(new_reading)

    # Alert on status/location change
    cause = _blockage_cause(region.id) if result["status"] != "NORMAL" else None

    changed = (
        prev is None
        or prev.status   != result["status"]
        or prev.location != result["location"]
    )
    if changed and result["status"] != "NORMAL":
        if cause and cause["material"] != "Not identified":
            msg = "Blockage {}, cause: {}".format(
                result["location"], cause["material"])
        else:
            msg = "; ".join(result["reasons"]) if result["reasons"] \
                  else result["status"]
        db.session.add(Alert(
            region_id=region.id, ts=now,
            status=result["status"], location=result["location"],
            message=msg,
        ))

    # ── Incident engine ─────────────────────────────────────────────────────
    # Flush first so the new reading is visible to update_incident's snapshot
    # query, then call the engine, then commit everything in one transaction.
    db.session.flush()
    update_incident(region, result, {
        "depth_b": reading["depth_b"],
        "flow":    reading["flow"],
    })

    db.session.commit()

    # Include the active incident (if any) in the reply to the ESP32.
    active_inc = (Incident.query
                  .filter_by(region_id=region.id, sensor_state="ACTIVE")
                  .first())

    reply = {
        "status":   result["status"],
        "location": result["location"],
        "buzzer":   result["status"] in ("BLOCKAGE", "CRITICAL"),
    }
    if cause:
        reply["blockage_cause"]            = cause["material"]
        reply["blockage_cause_confidence"] = cause["confidence"]
        reply["blockage_advice"]           = cause["advice"]
    if active_inc:
        reply["incident_id"] = active_inc.id
    return jsonify(reply)


@app.route("/api/material", methods=["POST"])
def api_material():
    """Receive a material detection from the ESP32 / simulator."""
    region = _region_from_key()
    if region is None:
        return jsonify({"error": "unauthorized"}), 401

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid or empty JSON body"}), 400

    material = data.get("material")
    if material not in MATERIALS:
        return jsonify({"error": "invalid material"}), 400

    confidence = data.get("confidence")
    if confidence is None or isinstance(confidence, bool):
        return jsonify({"error": "confidence is missing or not a number"}), 400
    try:
        confidence = float(confidence)
    except (TypeError, ValueError):
        return jsonify({"error": "confidence is not a number"}), 400
    if confidence < 0 or confidence > 1:
        return jsonify({"error": "confidence must be between 0 and 1"}), 400

    ir_detected = data.get("ir_detected")
    if not isinstance(ir_detected, bool):
        return jsonify({"error": "ir_detected must be true or false"}), 400

    if confidence < CONFIDENCE_THRESHOLD:
        material = "UNKNOWN"

    now = time.time()

    new_mat = Material(
        region_id=region.id, ts=now,
        material=material, confidence=confidence, ir_detected=ir_detected,
    )
    db.session.add(new_mat)
    db.session.flush()   # get the id so the LIMIT 2 query below sees it

    # Alert when material changes
    prev_rows = (Material.query
                 .filter_by(region_id=region.id)
                 .order_by(Material.id.desc())
                 .limit(2).all())
    prev_material = prev_rows[1].material if len(prev_rows) > 1 else None

    if prev_material != material:
        msg = "Detected {} ({:.0%} confidence".format(material, confidence)
        if ir_detected:
            msg += ", IR object detected"
        msg += ")"
        db.session.add(Alert(
            region_id=region.id, ts=now,
            status="MATERIAL", location="", message=msg,
        ))

    # ── Update active incident if a confident material is now known ──────────
    if material != "UNKNOWN" and confidence >= CONFIDENCE_THRESHOLD:
        active_inc = (Incident.query
                      .filter_by(region_id=region.id, sensor_state="ACTIVE")
                      .first())
        if active_inc is not None:
            active_inc.material            = material
            active_inc.material_confidence = confidence
            _refresh_plan(active_inc)

    db.session.commit()
    return jsonify({"material": material, "confidence": confidence,
                    "ir_detected": ir_detected})

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard API (login required, region-scoped)
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/api/latest")
@login_required
def api_latest():
    """Return the latest reading, analysis result, config for this region."""
    user   = _current_user()
    region = _region_for_session(user)

    if region is None:
        return jsonify({"has_data": False, "config": CFG, "material": None})

    db_rows = (Reading.query
               .filter_by(region_id=region.id)
               .order_by(Reading.id.desc())
               .limit(CFG["WINDOW"])
               .all())

    if not db_rows:
        return jsonify({
            "has_data": False,
            "config": CFG,
            "region_name": region.name,
            "material": _latest_material(region.id),
            "incident": _active_incident_dict(region.id),
        })

    rows = [
        {"ts": r.ts, "depth_a": r.depth_a, "depth_b": r.depth_b,
         "depth_c": r.depth_c, "flow": r.flow}
        for r in reversed(db_rows)
    ]
    latest = db_rows[0]   # most recent
    result = analyse(rows)

    age_s = round(time.time() - latest.ts, 1)

    return jsonify({
        "has_data": True,
        "age_s": age_s,
        "config": CFG,
        "region_name": region.name,
        "latest": {
            "ts": latest.ts,
            "depth_a": latest.depth_a, "depth_b": latest.depth_b,
            "depth_c": latest.depth_c, "flow": latest.flow,
            "temp": latest.temp,
        },
        "material": _latest_material(region.id),
        "blockage_cause": (
            _blockage_cause(region.id) if result["status"] != "NORMAL" else None
        ),
        "analysis": result,
        # Active incident for the "Recommended action" card on the dashboard.
        "incident": _active_incident_dict(region.id),
    })


@app.route("/api/history")
@login_required
def api_history():
    """Return the last n readings (max 500), oldest first."""
    user   = _current_user()
    region = _region_for_session(user)
    if region is None:
        return jsonify({"readings": []})

    n = min(max(1, request.args.get("n", 60, type=int)), 500)
    db_rows = (Reading.query
               .filter_by(region_id=region.id)
               .order_by(Reading.id.desc())
               .limit(n)
               .all())
    rows = [
        {"ts": r.ts, "depth_a": r.depth_a, "depth_b": r.depth_b,
         "depth_c": r.depth_c, "flow": r.flow, "temp": r.temp,
         "status": r.status, "location": r.location}
        for r in reversed(db_rows)
    ]
    return jsonify({"readings": rows})


@app.route("/api/alerts")
@login_required
def api_alerts():
    """Return the latest n alerts, newest first."""
    user   = _current_user()
    region = _region_for_session(user)
    if region is None:
        return jsonify({"alerts": []})

    n = min(max(1, request.args.get("n", 10, type=int)), 500)
    db_rows = (Alert.query
               .filter_by(region_id=region.id)
               .order_by(Alert.id.desc())
               .limit(n)
               .all())
    return jsonify({
        "alerts": [
            {"ts": a.ts, "status": a.status,
             "location": a.location, "message": a.message}
            for a in db_rows
        ]
    })


@app.route("/api/incidents")
@login_required
def api_incidents():
    """Return recent incidents for the user's region, newest first."""
    user   = _current_user()
    region = _region_for_session(user)
    if region is None:
        return jsonify({"incidents": []})

    limit = min(max(1, request.args.get("limit", 20, type=int)), 200)
    rows  = (Incident.query
             .filter_by(region_id=region.id)
             .order_by(Incident.id.desc())
             .limit(limit)
             .all())
    return jsonify({"incidents": [_incident_dict(r) for r in rows]})

# ─────────────────────────────────────────────────────────────────────────────
# Dashboard page
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/")
@login_required
def index():
    """Serve the dashboard page."""
    user   = _current_user()
    region = _region_for_session(user)
    # An admin who hasn't picked a region yet has nothing to show on the
    # dashboard; send them to the admin panel to choose one.
    if user.role == "admin" and region is None:
        return redirect(url_for("admin"))
    return render_template(
        "index.html",
        user=user,
        region=region,
    )

# ─────────────────────────────────────────────────────────────────────────────
# Auth routes
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    # Already logged in
    if _current_user():
        return redirect(url_for("index"))

    error         = None
    selected_role = "operator"   # keeps the toggle on the right tab after failure

    if request.method == "POST":
        if not _csrf_ok():
            error = "Invalid request. Please try again."
        else:
            login_id = request.form.get("login_id", "").strip()
            password = request.form.get("password", "")
            role     = request.form.get("role", "operator")
            # Sanitise: only the two known values are accepted
            if role not in ("operator", "admin"):
                role = "operator"
            selected_role = role

            ip_key = "ip:{}".format(request.remote_addr)
            id_key = "id:{}".format(login_id)

            if _is_blocked(ip_key) or _is_blocked(id_key):
                error = "Too many failed attempts. Try again in 5 minutes."
            else:
                user = User.query.filter_by(login_id=login_id).first()
                # Accept only when: user exists, password is correct,
                # AND the user's actual role matches what was selected.
                # Every other combination shows the same neutral message so
                # callers cannot enumerate roles.
                if user and user.check_password(password) and user.role == role:
                    _clear_failures(ip_key)
                    _clear_failures(id_key)
                    session.permanent = True
                    session["user_id"] = user.id
                    user.last_login_at = datetime.now(timezone.utc)
                    db.session.commit()
                    if user.role == "admin":
                        return redirect(url_for("admin"))
                    # Operator: honour a safe relative "next" parameter
                    next_url = request.args.get("next", "")
                    if next_url.startswith("/") and not next_url.startswith("//"):
                        return redirect(next_url)
                    return redirect(url_for("index"))
                else:
                    _record_failure(ip_key)
                    _record_failure(id_key)
                    error = "User not found or incorrect password"

    csrf = _csrf_token()
    return render_template("login.html", error=error, csrf_token=csrf,
                           selected_role=selected_role)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user  = _current_user()
    error = None
    success = None

    if request.method == "POST":
        if not _csrf_ok():
            error = "Invalid request. Please try again."
        else:
            current  = request.form.get("current_password", "")
            new_pw   = request.form.get("new_password", "")
            confirm  = request.form.get("confirm_password", "")

            if not user.check_password(current):
                error = "Current password is incorrect."
            elif len(new_pw) < 8:
                error = "New password must be at least 8 characters."
            elif new_pw == current:
                error = "New password must be different from the current one."
            elif new_pw != confirm:
                error = "Passwords do not match."
            else:
                user.set_password(new_pw)
                user.must_change_password = False
                db.session.commit()
                return redirect(url_for("index"))

    csrf = _csrf_token()
    return render_template(
        "change_password.html", user=user, error=error, success=success,
        csrf_token=csrf,
    )

# ─────────────────────────────────────────────────────────────────────────────
# Admin page
# ─────────────────────────────────────────────────────────────────────────────

@app.route("/admin", methods=["GET", "POST"])
@admin_required
def admin():
    user  = _current_user()
    error = None
    info  = None
    csrf  = _csrf_token()

    if request.method == "POST":
        if not _csrf_ok():
            error = "Invalid request. Please try again."
        else:
            action = request.form.get("action", "")

            if action == "select_region":
                rid = request.form.get("region_id", type=int)
                region = db.session.get(Region, rid)
                if region:
                    session["admin_region_id"] = region.id
                    return redirect(url_for("index"))
                error = "Region not found."

            elif action == "create_region":
                name = request.form.get("name", "").strip()
                code = request.form.get("code", "").strip()
                if not name or not code:
                    error = "Name and code are required."
                elif Region.query.filter_by(code=code).first():
                    error = "A region with that code already exists."
                else:
                    key = secrets.token_urlsafe(32)
                    db.session.add(Region(name=name, code=code, device_key=key))
                    db.session.commit()
                    info = "Region created. Device key: {}".format(key)

            elif action == "create_operator":
                login_id  = request.form.get("login_id", "").strip()
                rid       = request.form.get("region_id", type=int)
                tmp_pw    = secrets.token_urlsafe(10)
                region    = db.session.get(Region, rid)
                if not login_id or not region:
                    error = "Login ID and region are required."
                elif User.query.filter_by(login_id=login_id).first():
                    error = "A user with that login ID already exists."
                else:
                    u = User(login_id=login_id, role="operator",
                             region_id=region.id, must_change_password=True)
                    u.set_password(tmp_pw)
                    db.session.add(u)
                    db.session.commit()
                    info = "Operator created. Temporary password: {}".format(tmp_pw)

            elif action == "reset_password":
                uid    = request.form.get("user_id", type=int)
                target = db.session.get(User, uid)
                if not target:
                    error = "User not found."
                else:
                    tmp_pw = secrets.token_urlsafe(10)
                    target.set_password(tmp_pw)
                    target.must_change_password = True
                    db.session.commit()
                    info = "Password reset for {}. Temporary password: {}".format(
                        target.login_id, tmp_pw)

    regions = Region.query.order_by(Region.name).all()
    users   = User.query.order_by(User.login_id).all()
    return render_template(
        "admin.html", user=user, regions=regions, users=users,
        error=error, info=info, csrf_token=csrf,
        selected_region_id=session.get("admin_region_id"),
    )

# ─────────────────────────────────────────────────────────────────────────────
# Bootstrap: create tables and seed admin at import time
# ─────────────────────────────────────────────────────────────────────────────

with app.app_context():
    db.create_all()

    # Create admin if users table is empty and env vars are provided
    _admin_username = os.environ.get("ADMIN_USERNAME", "")
    _admin_password = os.environ.get("ADMIN_PASSWORD", "")
    if _admin_username and _admin_password:
        if User.query.count() == 0:
            admin_user = User(login_id=_admin_username, role="admin",
                              region_id=None, must_change_password=False)
            admin_user.set_password(_admin_password)
            db.session.add(admin_user)
            db.session.commit()
            print("INFO: Admin user '{}' created from environment.".format(
                _admin_username))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
