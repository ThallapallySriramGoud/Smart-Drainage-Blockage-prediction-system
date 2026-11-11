"""
Smart Drainage Monitoring System - Flask Backend

Receives water-level, flow and temperature readings from an ESP32 (or the
simulator), stores them in SQLite, analyses them for developing blockages,
and serves a live dashboard at http://localhost:5000.

Run:  python app.py
Then: open http://localhost:5000 in a browser
      run python simulate.py in another terminal to feed test data
"""

import sqlite3
import time
from flask import Flask, request, jsonify, render_template, g

app = Flask(__name__)

# ---------------------------------------------------------------------------
# CONFIG - edit these values to match your channel and sensors
# ---------------------------------------------------------------------------
CFG = {
    "CHANNEL_CM":       15,    # total depth of the channel in cm
    "OVERFLOW_CM":      12,    # depth (cm) at which overflow is imminent
    "GRADIENT_CM":       2.0,  # depth difference (cm) between two points suggesting a blockage
    "RISE_CM_PER_MIN":   0.5,  # rate of rise (cm/min) considered "rising fast"
    "NORMAL_FLOW_LPM":   4.0,  # normal flow rate in litres per minute
    "FLOW_DROP_RATIO":   0.6,  # flow below this fraction of normal counts as "low"
    "MIN_DEPTH_CM":      1.0,  # below this depth the channel is "dry" (no false alarms)
    "WINDOW":            15,   # number of recent readings to analyse
    "MIN_READINGS":      8,     # need at least this many readings before warning/blockage
    "OFFLINE_AFTER_S":   30,    # sensor considered offline after this many seconds
}

# API key that the ESP32 must send in the X-API-Key header
API_KEY = "change-me"

# SQLite database file (created automatically next to app.py)
DB_PATH = "drainage.db"


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """Return a database connection for this request, creating one if needed."""
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row   # lets us access columns by name
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    """Close the database at the end of every request."""
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Create the tables if they do not exist yet."""
    conn = sqlite3.connect(DB_PATH)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS readings (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        REAL NOT NULL,
            depth_a   REAL NOT NULL,
            depth_b   REAL NOT NULL,
            depth_c   REAL NOT NULL,
            flow      REAL NOT NULL,
            temp      REAL NOT NULL,
            status    TEXT NOT NULL,
            location  TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        REAL NOT NULL,
            status    TEXT NOT NULL,
            location  TEXT NOT NULL DEFAULT '',
            message   TEXT NOT NULL
        );
    """)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Detection logic
# ---------------------------------------------------------------------------

def _smooth(rows, key):
    """Average of the last 3 readings for the given column."""
    recent = rows[-3:]
    return sum(r[key] for r in recent) / len(recent)


def _slope(rows, key):
    """
    Least-squares slope of the given column over the window.
    Returns the trend in units per minute.

    Timestamps are centred (each value minus the mean) before the regression
    to avoid floating-point loss when Unix timestamps are large.
    """
    # Convert Unix timestamps (seconds) to minutes so slope is "per minute"
    xs = [r["ts"] / 60.0 for r in rows]
    ys = [r[key] for r in rows]
    n = len(xs)
    mean_x = sum(xs) / n
    mean_y = sum(ys) / n
    # Centered formula: slope = sum(dx*dy) / sum(dx^2)
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

    Parameters:
        rows: list of dict-like rows (oldest first), each containing
              ts, depth_a, depth_b, depth_c, flow.

    Returns a dict:
        status    NORMAL | WARNING | BLOCKAGE | CRITICAL
        location  "" | "A-B" | "B-C" | "after C"
        score     int (0-4) for the winning segment
        reasons   list of plain-English strings
        eta_min   minutes until overflow (float) or None
        slopes    dict of slopes for depth_a, depth_b, depth_c, flow
    """
    # --- Not enough data yet -> everything is fine -----------------------
    if len(rows) < CFG["MIN_READINGS"]:
        return {
            "status": "NORMAL",
            "location": "",
            "score": 0,
            "reasons": [],
            "eta_min": None,
            "slopes": {},
        }

    # --- 1. Smooth latest values (average of last 3 readings) ------------
    s_a    = _smooth(rows, "depth_a")
    s_b    = _smooth(rows, "depth_b")
    s_c    = _smooth(rows, "depth_c")
    s_flow = _smooth(rows, "flow")

    # --- 2. Trend (slope) of each value in units per minute --------------
    slope_a    = _slope(rows, "depth_a")
    slope_b    = _slope(rows, "depth_b")
    slope_c    = _slope(rows, "depth_c")
    slope_flow = _slope(rows, "flow")
    slopes = {
        "depth_a": round(slope_a, 3),
        "depth_b": round(slope_b, 3),
        "depth_c": round(slope_c, 3),
        "flow":    round(slope_flow, 3),
    }

    # --- 3. Is the flow abnormally low? ----------------------------------
    flow_low = (s_flow < CFG["NORMAL_FLOW_LPM"] * CFG["FLOW_DROP_RATIO"]
                and s_a > CFG["MIN_DEPTH_CM"])
    flow_reason = "Flow low ({:.1f} L/min)".format(s_flow)

    # --- 4. Score each possible blockage location ------------------------
    # Each segment keeps its own score, reasons list, and a "diff" value
    # used as a tie-breaker when two segments have the same score.
    seg_ab = {"score": 0, "reasons": [], "diff": s_a - s_b}
    seg_bc = {"score": 0, "reasons": [], "diff": s_b - s_c}
    seg_ac = {"score": 0, "reasons": [], "diff": 0}   # "after C"

    # Segment A-B: water deeper at A than B (back-up upstream of blockage)
    if (s_a - s_b) >= CFG["GRADIENT_CM"]:
        seg_ab["score"] += 2
        seg_ab["reasons"].append(
            "Water is {:.1f} cm deeper at A than at B".format(s_a - s_b))
    if slope_a >= CFG["RISE_CM_PER_MIN"]:
        seg_ab["score"] += 1
        seg_ab["reasons"].append(
            "Level at A rising {:.1f} cm/min".format(slope_a))
    if flow_low:
        seg_ab["score"] += 1
        seg_ab["reasons"].append(flow_reason)

    # Segment B-C: water deeper at B than C
    if (s_b - s_c) >= CFG["GRADIENT_CM"]:
        seg_bc["score"] += 2
        seg_bc["reasons"].append(
            "Water is {:.1f} cm deeper at B than at C".format(s_b - s_c))
    if slope_b >= CFG["RISE_CM_PER_MIN"]:
        seg_bc["score"] += 1
        seg_bc["reasons"].append(
            "Level at B rising {:.1f} cm/min".format(slope_b))
    if flow_low:
        seg_bc["score"] += 1
        seg_bc["reasons"].append(flow_reason)

    # After C: all three depths rising quickly
    if (slope_a >= CFG["RISE_CM_PER_MIN"]
            and slope_b >= CFG["RISE_CM_PER_MIN"]
            and slope_c >= CFG["RISE_CM_PER_MIN"]):
        seg_ac["score"] += 2
        seg_ac["reasons"].append("All depths rising rapidly")
    if flow_low:
        seg_ac["score"] += 1
        seg_ac["reasons"].append(flow_reason)

    # --- 5. Pick the highest-scoring segment -----------------------------
    # Tie-breaker: larger depth difference (upstream minus downstream).
    segments = [("A-B", seg_ab), ("B-C", seg_bc), ("after C", seg_ac)]
    best_loc, best = max(
        segments, key=lambda kv: (kv[1]["score"], kv[1]["diff"]))

    if best["score"] >= 3:
        status = "BLOCKAGE"
    elif best["score"] == 2:
        status = "WARNING"
    else:
        status = "NORMAL"

    location = best_loc if status in ("BLOCKAGE", "WARNING") else ""
    reasons = best["reasons"] if status in ("BLOCKAGE", "WARNING") else []

    # --- 6. CRITICAL override: any depth at or above overflow ------------
    max_depth = max(s_a, s_b, s_c)
    if max_depth >= CFG["OVERFLOW_CM"]:
        status = "CRITICAL"
        reasons = list(reasons)  # keep any existing reasons
        reasons.append(
            "Water depth {:.1f} cm is at or above the overflow level "
            "({:.0f} cm)".format(max_depth, CFG["OVERFLOW_CM"]))

    # --- 7. Estimate time to overflow -----------------------------------
    eta_min = None
    for depth, slope in [(s_a, slope_a), (s_b, slope_b), (s_c, slope_c)]:
        if slope > 0.1 and depth < CFG["OVERFLOW_CM"]:
            t = (CFG["OVERFLOW_CM"] - depth) / slope
            if eta_min is None or t < eta_min:
                eta_min = t
    if eta_min is not None:
        eta_min = round(eta_min, 1)

    return {
        "status": status,
        "location": location,
        "score": best["score"],
        "reasons": reasons,
        "eta_min": eta_min,
        "slopes": slopes,
    }


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

@app.route("/api/data", methods=["POST"])
def api_data():
    """Receive a reading from the ESP32 (or the simulator)."""
    # --- API key check --------------------------------------------------
    if request.headers.get("X-API-Key") != API_KEY:
        return jsonify({"error": "unauthorized"}), 401

    # --- Parse and validate JSON ----------------------------------------
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

    # --- Analyse recent readings + this new one -------------------------
    db = get_db()
    now = time.time()

    # Fetch last WINDOW-1 readings (we add the new one to make WINDOW total)
    rows = db.execute(
        "SELECT ts, depth_a, depth_b, depth_c, flow "
        "FROM readings ORDER BY id DESC LIMIT ?",
        (CFG["WINDOW"] - 1,)
    ).fetchall()
    rows = [dict(r) for r in reversed(rows)]  # oldest first

    # Append the incoming reading to the end
    rows.append({
        "ts": now,
        "depth_a": reading["depth_a"],
        "depth_b": reading["depth_b"],
        "depth_c": reading["depth_c"],
        "flow": reading["flow"],
    })

    result = analyse(rows)

    # --- Fetch previous reading's status for alert comparison -----------
    prev = db.execute(
        "SELECT status, location FROM readings ORDER BY id DESC LIMIT 1"
    ).fetchone()

    # --- Store the reading ----------------------------------------------
    db.execute(
        "INSERT INTO readings "
        "(ts, depth_a, depth_b, depth_c, flow, temp, status, location) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (now, reading["depth_a"], reading["depth_b"], reading["depth_c"],
         reading["flow"], reading["temp"], result["status"], result["location"])
    )

    # --- Log an alert only when (status, location) changes ---------------
    changed = (prev is None
               or prev["status"] != result["status"]
               or prev["location"] != result["location"])
    if changed and result["status"] != "NORMAL":
        message = "; ".join(result["reasons"]) if result["reasons"] \
                  else result["status"]
        db.execute(
            "INSERT INTO alerts (ts, status, location, message) "
            "VALUES (?, ?, ?, ?)",
            (now, result["status"], result["location"], message)
        )

    db.commit()

    # --- Reply to the ESP32 ---------------------------------------------
    return jsonify({
        "status": result["status"],
        "location": result["location"],
        "buzzer": result["status"] in ("BLOCKAGE", "CRITICAL"),
    })


@app.route("/api/latest")
def api_latest():
    """Return the latest reading, the analysis result, and config."""
    db = get_db()

    rows = db.execute(
        "SELECT ts, depth_a, depth_b, depth_c, flow, temp "
        "FROM readings ORDER BY id DESC LIMIT ?",
        (CFG["WINDOW"],)
    ).fetchall()

    if not rows:
        return jsonify({"has_data": False, "config": CFG})

    rows = [dict(r) for r in reversed(rows)]  # oldest first
    latest = rows[-1]
    result = analyse(rows)

    now = time.time()
    age_s = round(now - latest["ts"], 1)

    return jsonify({
        "has_data": True,
        "age_s": age_s,
        "config": CFG,
        "latest": {
            "ts": latest["ts"],
            "depth_a": latest["depth_a"],
            "depth_b": latest["depth_b"],
            "depth_c": latest["depth_c"],
            "flow": latest["flow"],
            "temp": latest["temp"],
        },
        "analysis": result,
    })


@app.route("/api/history")
def api_history():
    """Return the last n readings (max 500), oldest first for charts."""
    n = request.args.get("n", 60, type=int)
    n = min(max(1, n), 500)

    db = get_db()
    rows = db.execute(
        "SELECT ts, depth_a, depth_b, depth_c, flow, temp, status, location "
        "FROM readings ORDER BY id DESC LIMIT ?",
        (n,)
    ).fetchall()
    rows = [dict(r) for r in reversed(rows)]  # oldest first

    return jsonify({"readings": rows})


@app.route("/api/alerts")
def api_alerts():
    """Return the latest n alerts, newest first."""
    n = request.args.get("n", 10, type=int)
    n = min(max(1, n), 500)

    db = get_db()
    rows = db.execute(
        "SELECT ts, status, location, message FROM alerts "
        "ORDER BY id DESC LIMIT ?",
        (n,)
    ).fetchall()

    return jsonify({"alerts": [dict(r) for r in rows]})


@app.route("/")
def index():
    """Serve the dashboard page."""
    return render_template("index.html")


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)
