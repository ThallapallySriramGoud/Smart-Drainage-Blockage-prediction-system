# Smart Drainage Monitoring System

A web application that monitors an IoT drainage channel with three water-level
sensors (A upstream, B midstream, C downstream), one flow sensor, one
temperature sensor, and an object sensor that identifies debris material. It
detects where a blockage is developing, warns early before overflow, and shows
everything on a live dashboard.

The app works with simulated sensor data out of the box, and later accepts
real data from an ESP32 without any code changes.

## Tech stack

- **Backend:** Python 3.10+ with Flask
- **Database:** SQLite (sqlite3 module, no ORM)
- **Frontend:** Single HTML page with plain HTML, CSS and vanilla JavaScript
- **Charts:** Chart.js 4.4.1 from the jsDelivr CDN
- **Dependencies:** Flask, gunicorn (for production)

## Project structure

```
drainage-dashboard/
  app.py              # Flask backend (API + detection logic)
  simulate.py         # Simulator that POSTs readings like an ESP32
  requirements.txt     # Python dependencies (flask, gunicorn)
  templates/index.html # The dashboard page
```

## How to install and run

Open two terminals.

**Terminal 1 - start the server (local development):**

```bash
cd drainage-dashboard
pip install -r requirements.txt
python app.py
```

The server starts on `http://0.0.0.0:5000` so an ESP32 on the same Wi-Fi can
reach it. Open `http://localhost:5000` in a browser to see the dashboard.

**Terminal 2 - run the simulator (local):**

```bash
cd drainage-dashboard
# For local testing, point the simulator at localhost:
set SERVER_URL=http://localhost:5000
python simulate.py
```

The simulator sends 105 readings over about 3.5 minutes:

1. **Phase 1** (20 readings): normal flow, all depths ~4 cm, flow ~4 L/min
2. **Phase 2** (60 readings): a blockage builds between B and C - depth B
   rises, depth C drops, flow decreases. A PLASTIC object is detected by the
   IR sensor periodically.
3. **Phase 3** (25 readings): the blockage clears, the object is cleared, and
   everything returns to normal

Watch the dashboard transition: **Normal &rarr; Early warning &rarr;
Blockage confirmed (B-C, PLASTIC) &rarr; Normal**. Alerts are logged in the
alert table at each status change and each new material detection.

### Production deployment (Render)

The app is deployed on Render with gunicorn. The start command is:

```bash
gunicorn app:app
```

The simulator defaults to the Render URL. To run it against the deployed
server, simply:

```bash
python simulate.py
```

## Connecting a real ESP32

The ESP32 sends POST requests with header `X-API-Key: change-me` (must match
`API_KEY` in `app.py`).

**Water-level and flow data** - POST to `/api/data`:

```json
{"depth_a": 4.2, "depth_b": 4.1, "depth_c": 3.9, "flow": 3.8, "temp": 27.5}
```

Reply:
```json
{"status": "NORMAL", "location": "", "buzzer": false}
```

`buzzer` is `true` for BLOCKAGE and CRITICAL, so the ESP32 can drive a buzzer
and display the status on a 16x2 LCD.

**Material identification** - POST to `/api/material`:

```json
{"material": "PLASTIC", "confidence": 0.85, "ir_detected": true}
```

`material` must be one of: `ROCK`, `PLASTIC`, `RUBBER`, `WOOD`, `OTHER`,
`UNKNOWN`. If `confidence` is below 0.6, the server stores it as `UNKNOWN`.

Reply:
```json
{"material": "PLASTIC", "confidence": 0.85, "ir_detected": true}
```

Change `API_KEY` in `app.py` to your own secret key before deploying.

## Blockage confirmation

A blockage is marked as **confirmed** when both the water-level difference
(depth gradient >= GRADIENT_CM) and low flow (flow < NORMAL_FLOW_LPM x
FLOW_DROP_RATIO) agree on the same channel segment. The dashboard shows
"Blockage confirmed" instead of "Blockage detected", along with the last
detected material.

## Configuration

All thresholds are in the `CFG` dictionary at the top of `app.py`:

| Key | Default | Meaning |
|-----|---------|---------|
| CHANNEL_CM | 15 | Total channel depth in cm |
| OVERFLOW_CM | 12 | Depth at which overflow is imminent |
| GRADIENT_CM | 2.0 | Depth difference between two points suggesting a blockage |
| RISE_CM_PER_MIN | 0.5 | Rate of rise considered "rising fast" |
| NORMAL_FLOW_LPM | 4.0 | Normal flow rate in L/min |
| FLOW_DROP_RATIO | 0.6 | Flow below this fraction of normal counts as "low" |
| MIN_DEPTH_CM | 1.0 | Below this depth the channel is "dry" (no false alarms) |
| WINDOW | 15 | Number of recent readings to analyse |
| MIN_READINGS | 8 | Minimum readings before warning/blockage |
| OFFLINE_AFTER_S | 30 | Sensor considered offline after this many seconds |

The simulator's server URL can be overridden with the `SERVER_URL`
environment variable (defaults to the Render deployment URL).

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/data` | Receive a water-level reading (requires X-API-Key) |
| POST | `/api/material` | Receive a material detection (requires X-API-Key) |
| GET | `/api/latest` | Latest values, analysis, material, age and config |
| GET | `/api/history?n=60` | Last n readings (max 500) |
| GET | `/api/alerts?n=10` | Latest alerts, newest first |
| GET | `/` | The dashboard page |
