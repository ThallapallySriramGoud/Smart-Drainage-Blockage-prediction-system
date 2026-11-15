"""
playbook.py – Field response plans for drainage blockages.

NOTE: This is general guidance only.  Always follow your local authority's
safety rules, risk assessments and confined-space entry procedures.  Local
rules always take precedence over this playbook.

Usage
-----
    from playbook import get_plan
    plan = get_plan("PLASTIC", "BLOCKAGE", "B-C")

Self-test: run this file directly:
    python playbook.py
"""

# ── Plan database ─────────────────────────────────────────────────────────────

_PLANS = {
    "PLASTIC": {
        "title":        "Remove plastic debris",
        "crew":         "2 people",
        "est_time_min": 45,
        "steps": [
            "Confirm the obstruction from the inspection point before entering the area.",
            "Pull out bags and bottles with a grab tool, then clear the remainder by hand.",
            "Push a drain rod through the pipe to confirm the line is fully open.",
            "Bag all waste for proper disposal; do not leave debris on site.",
            "Flush with water and confirm that flow and depth levels return to normal.",
        ],
        "tools": [
            "Grab tool or litter picker",
            "Drain rods",
            "Protective gloves",
            "Waste bags",
            "Bucket",
        ],
    },
    "SAND": {
        "title":        "Clear silt and sand accumulation",
        "crew":         "2 people",
        "est_time_min": 60,
        "steps": [
            "Open the inspection cover and measure the depth of the silt deposit.",
            "Loosen the material with a rake or rod before flushing.",
            "Flush with high-pressure jetting, or remove with a suction pump if jetting is unavailable.",
            "Inspect the channel slope and identify any upstream source feeding the sand build-up.",
            "Repeat flushing until depth and flow levels equalise across all points.",
        ],
        "tools": [
            "Jetting machine or pressure hose",
            "Suction / vacuum pump",
            "Shovel",
            "Bucket",
        ],
    },
    "GRAVEL": {
        "title":        "Remove gravel accumulation",
        "crew":         "2 people",
        "est_time_min": 60,
        "steps": [
            "Remove loose gravel with a shovel or long-handled scoop.",
            "Flush the remaining fine particles with water.",
            "Assess whether a gravel trap is needed upstream to prevent recurrence.",
            "Test the flow and check that depth readings equalise.",
        ],
        "tools": [
            "Shovel",
            "Long-handled scoop",
            "Wheelbarrow",
            "Pressure hose",
        ],
    },
    "ROCK": {
        "title":        "Remove rock or large stone",
        "crew":         "3 people",
        "est_time_min": 75,
        "steps": [
            "Assess the size and weight of the object before attempting removal.",
            "Do NOT attempt to lift anything heavy alone — always use two or more people.",
            "Break it up with a bar or lever it out using a crowbar if size permits.",
            "Lift out as a team; use rope or chain if needed.",
            "Check the pipe and channel walls for damage caused by the obstruction.",
            "Test the flow to confirm the channel is clear.",
        ],
        "tools": [
            "Lifting bar",
            "Crowbar",
            "Rope or chain",
            "Protective gloves",
            "Safety boots",
            "Wheelbarrow",
        ],
    },
    "WOOD": {
        "title":        "Remove wood or branch debris",
        "crew":         "2 people",
        "est_time_min": 50,
        "steps": [
            "Cut long pieces into manageable sections with a hand saw or loppers.",
            "Pull pieces out using a hook or rake; avoid pushing them further downstream.",
            "Clear any small debris and leaves left behind.",
            "Check for further branches or root material lodged upstream.",
            "Test the flow and confirm depth readings return to normal.",
        ],
        "tools": [
            "Hand saw",
            "Loppers",
            "Rake or hook",
            "Protective gloves",
            "Waste bags",
        ],
    },
    "RUBBER": {
        "title":        "Remove rubber or flexible object",
        "crew":         "2 people",
        "est_time_min": 45,
        "steps": [
            "Pull the item out with a grab tool or hook.",
            "If wedged or compressed, cut it into smaller pieces with a utility knife to release it.",
            "Clear any residual material and check for damage to the channel lining.",
            "Test the flow to confirm the channel is fully open.",
        ],
        "tools": [
            "Grab tool",
            "Hook",
            "Utility knife",
            "Protective gloves",
            "Waste bags",
        ],
    },
    "OTHER": {
        "title":        "Remove unclassified obstruction",
        "crew":         "2 people",
        "est_time_min": 60,
        "steps": [
            "Inspect the blockage and photograph it for the incident record.",
            "Remove what is visible using hand tools.",
            "If the object cannot be identified or moved safely, stop and call a supervisor.",
            "Test the flow once the obstruction is cleared.",
        ],
        "tools": [
            "Torch",
            "Grab tool",
            "Drain rod",
            "Protective gloves",
            "Waste bags",
        ],
    },
    "UNKNOWN": {
        "title":        "Inspect before acting",
        "crew":         "2 people",
        "est_time_min": 30,
        "steps": [
            "Send a person to visually inspect the channel between points B and C.",
            "Photograph and identify the material, then update the system with the correct type.",
            "Once identified, follow the plan for that specific material.",
        ],
        "tools": [
            "Torch",
            "Camera or phone",
            "Protective gloves",
            "Drain rod",
        ],
    },
}

# Safety notes that appear on every plan.
_SAFETY = [
    "Wear protective gloves, safety boots, a high-visibility vest and eye protection.",
    "Never enter a drain or confined space without trained staff present and a gas check completed"
    " — drain gases can be toxic or flammable.",
    "Use cones or barrier tape if the work area is open to traffic or members of the public.",
    "Wash hands thoroughly after completing the work.",
    "Do not work alone.",
]

# Extra steps prepended when severity is CRITICAL.
_CRITICAL_EXTRA_STEPS = [
    "Warn people nearby and keep them away from the overflow area.",
    "Place a pump to lower the water level at point B.",
    "Inform your supervisor immediately.",
]

# ── Location description helper ───────────────────────────────────────────────

def _location_description(location):
    """Return a human-readable description of the blockage location."""
    descriptions = {
        "A-B":     "Blockage between points A and B: water is backing up at A",
        "B-C":     "Blockage between points B and C: water is backing up at B",
        "after C": "Blockage after point C: water is backing up at all points",
    }
    return descriptions.get(location, "Blockage detected: water levels are rising")


# ── Public API ────────────────────────────────────────────────────────────────

def get_plan(material, severity, location):
    """
    Return a response plan dict for the given material, severity and location.

    Parameters
    ----------
    material : str
        One of PLASTIC, SAND, GRAVEL, ROCK, WOOD, RUBBER, OTHER, UNKNOWN.
        Unknown values fall back to OTHER.
    severity : str
        "BLOCKAGE" or "CRITICAL".
    location : str
        Channel segment string, e.g. "B-C", "A-B", "after C".

    Returns
    -------
    dict with keys:
        title          (str)
        summary        (str)  – includes the location
        urgency        (str)  – "URGENT" or "ROUTINE"
        steps          (list of str)
        tools          (list of str)
        safety         (list of str)
        crew           (str)
        est_time_min   (int)
        note           (str)  – disclaimer
    """
    base = _PLANS.get(material, _PLANS["OTHER"])

    urgency = "URGENT" if severity == "CRITICAL" else "ROUTINE"
    steps   = list(base["steps"])
    time_min = base["est_time_min"]

    if severity == "CRITICAL":
        # Prepend emergency steps and reduce time estimate (the pump handles
        # much of the waiting, so the hands-on work starts sooner).
        steps = _CRITICAL_EXTRA_STEPS + steps
        time_min = max(10, int(time_min * 2 // 3))

    summary = _location_description(location)

    return {
        "title":        base["title"],
        "summary":      summary,
        "urgency":      urgency,
        "steps":        steps,
        "tools":        list(base["tools"]),
        "safety":       list(_SAFETY),
        "crew":         base["crew"],
        "est_time_min": time_min,
        "note": (
            "This is general guidance only.  Always follow your local "
            "authority's safety rules, risk assessments and confined-space "
            "procedures.  Local rules take precedence."
        ),
    }


# ── Self-test ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    print("=== Sample plan: PLASTIC / BLOCKAGE / B-C ===")
    plan = get_plan("PLASTIC", "BLOCKAGE", "B-C")
    print(json.dumps(plan, indent=2))

    print()
    print("=== Sample plan: ROCK / CRITICAL / A-B ===")
    plan2 = get_plan("ROCK", "CRITICAL", "A-B")
    print(json.dumps(plan2, indent=2))

    print()
    print("=== Sample plan: UNKNOWN / BLOCKAGE / after C ===")
    plan3 = get_plan("UNKNOWN", "BLOCKAGE", "after C")
    print(json.dumps(plan3, indent=2))
