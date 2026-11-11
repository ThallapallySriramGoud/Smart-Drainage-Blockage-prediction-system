# Smart Drainage Monitoring System

A software-only web application that monitors an IoT drainage channel with
three water-level sensors (A upstream, B midstream, C downstream), one flow
sensor and one temperature sensor. It detects where a blockage is developing,
warns early before overflow, and shows everything on a live dashboard.

The app works with simulated sensor data out of the box, and later accepts
real data from an ESP32 without any code changes.

## Tech stack

- **Backend:** Python 3.10+ with Flask
- **Database:** SQLite (sqlite3 module, no ORM)
- **Frontend:** Single HTML page with plain HTML, CSS and vanilla JavaScript
- **Charts:** Chart.js 4.4.1 from the jsDelivr CDN
- **Only dependency:** Flask

## Project structure

```
drainage-dashboard/
  app.py              # Flask backend (API + detection logic)
  simulate.py         # Simulator that POSTs readings like an ESP32
  requirements.txt     # Python dependencies (just flask)
  templates/index.html # The dashboard page
```

## How to install and run

Open two terminals.

**Terminal 1 - start the server:**

```bash
cd drainage-dashboard
pip install -r requirements.txt
python app.py
```

The server starts on `http://0.0.0.0:5000` so an ESP32 on the same Wi-Fi can
reach it. Open `http://localhost:5000` in a browser to see the dashboard.

**Terminal 2 - run the simulator:**

```bash
cd drainage-dashboard
python simulate.py
```

The simulator sends 105 readings over about 3.5 minutes:

1. **Phase 1** (20 readings): normal flow, all depths ~4 cm, flow ~4 L/min
2. **Phase 2** (60 readings): a blockage builds between B and C - depth B
   rises, depth C drops, flow decreases
3. **Phase 3** (25 readings): the blockage clears and everything returns to
   normal

Watch the dashboard transition: **Normal &rarr; Early warning &rarr;
Blockage detected (B-C) &rarr; Normal**. Alerts are logged in the alert
table at each status change.

## Connecting a real ESP32

The ESP32 sends a POST request to `http://<server-ip>:5000/api/data` with:

- Header `X-API-Key: change-me` (must match `API_KEY` in `app.py`)
- JSON body: `{"depth_a": 4.2, "depth_b": 4.1, "depth_c": 3.9,
  "flow": 3.8, "temp": 27.5}`

The server replies with:

```json
{"status": "NORMAL", "location": "", "buzzer": false}
```

`buzzer` is `true` for BLOCKAGE and CRITICAL, so the ESP32 can drive a buzzer
and display the status on a 16x2 LCD.

Change `API_KEY` in `app.py` to your own secret key before deploying.

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

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/data` | Receive a reading (requires X-API-Key header) |
| GET | `/api/latest` | Latest values, analysis result, age and config |
| GET | `/api/history?n=60` | Last n readings (max 500) |
| GET | `/api/alerts?n=10` | Latest alerts, newest first |
| GET | `/` | The dashboard page |
