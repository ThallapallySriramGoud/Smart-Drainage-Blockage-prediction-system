"""
Smart Drainage Monitoring System - Simulator

Pretends to be the ESP32 and POSTs readings to the server every 2 seconds.
Three phases:
  1. 20 readings of normal flow
  2. 60 readings of a blockage building between B and C
  3. 25 readings of the blockage clearing back to normal

Run:  python simulate.py
(make sure app.py is already running)

Note: the flow drop rate is -0.15 per step (steeper than a real sensor would
need) so that the dashboard clearly shows the transition
Normal -> Early warning -> Blockage -> Normal within the demo.
"""

import urllib.request
import urllib.error
import json
import time
import random

URL = "http://localhost:5000/api/data"
API_KEY = "change-me"


def send(payload):
    """POST a reading to the server and print the reply."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        URL,
        data=body,
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            reply = json.loads(resp.read())
            print("    -> status={} location={} buzzer={}".format(
                reply.get("status", "?"),
                reply.get("location", ""),
                reply.get("buzzer", "?")))
            return reply
    except urllib.error.HTTPError as e:
        print("    -> HTTP {}: {}".format(e.code, e.read().decode()))
    except urllib.error.URLError as e:
        print("    -> Cannot reach server: {}".format(e.reason))
    except Exception as e:
        print("    -> Error: {}".format(e))
    return None


def noise(std):
    """Gaussian noise with the given standard deviation."""
    return random.gauss(0, std)


def make_payload(a, b, c, flow, temp):
    """Build a JSON payload with Gaussian noise added to each value."""
    return {
        "depth_a": round(a + noise(0.08), 2),
        "depth_b": round(b + noise(0.08), 2),
        "depth_c": round(c + noise(0.08), 2),
        "flow":    round(flow + noise(0.1), 2),
        "temp":    round(temp + noise(0.08), 2),
    }


def main():
    print("=" * 60)
    print("  Smart Drainage Monitoring System - Simulator")
    print("  Make sure app.py is running on http://localhost:5000")
    print("=" * 60)
    print()

    # Base values that we will modify during the phases
    a, b, c, flow, temp = 4.0, 4.0, 4.0, 4.0, 27.5
    interval = 2  # seconds between readings

    # --- Phase 1: Normal flow (20 readings) ------------------------------
    print("--- Phase 1: Normal flow (20 readings) ---")
    for i in range(20):
        payload = make_payload(a, b, c, flow, temp)
        print("[{:3d}] {}".format(i + 1, payload))
        send(payload)
        time.sleep(interval)

    # --- Phase 2: Blockage building between B and C (60 readings) --------
    # depth_b rises fast (water backs up behind the blockage)
    # depth_a rises slowly (some back-up effect upstream)
    # depth_c drops (less water getting through)
    # flow drops (blockage restricts flow)
    print()
    print("--- Phase 2: Blockage building between B and C (60 readings) ---")
    for i in range(60):
        b    += 0.10
        a    += 0.03
        c     = max(1.0, c - 0.04)
        flow  = max(0.5, flow - 0.15)   # steeper drop so flow_low triggers early
        payload = make_payload(a, b, c, flow, temp)
        print("[{:3d}] {}".format(i + 21, payload))
        send(payload)
        time.sleep(interval)

    # --- Phase 3: Blockage clearing back to normal (25 readings) --------
    # Linearly interpolate from current values back to normal
    print()
    print("--- Phase 3: Blockage clearing (25 readings) ---")
    start_a, start_b, start_c, start_flow = a, b, c, flow
    for i in range(25):
        frac = (i + 1) / 25.0
        a    = start_a    + (4.0 - start_a)    * frac
        b    = start_b    + (4.0 - start_b)    * frac
        c    = start_c    + (4.0 - start_c)    * frac
        flow = start_flow + (4.0 - start_flow) * frac
        payload = make_payload(a, b, c, flow, temp)
        print("[{:3d}] {}".format(i + 81, payload))
        send(payload)
        time.sleep(interval)

    print()
    print("Simulator finished. Check the dashboard for the final state.")


if __name__ == "__main__":
    main()
