from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

import ipaddress
import time
import requests

from backend.parser import (
    read_events,
    summarize_events,
    calculate_severity,
)


app = FastAPI(
    title="BaitTrace API",
    description="Cybersecurity Honeypot Monitoring API",
    version="1.0.0",
)


# =========================================================
# CORS
# =========================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =========================================================
# IP GEOLOCATION CACHE
# =========================================================

# Stores previously resolved IP addresses so we do not
# repeatedly ask the geolocation service for the same IP.

GEO_CACHE = {}

# Cache geolocation results for 24 hours.

GEO_CACHE_TTL = 24 * 60 * 60


def is_public_ip(ip):
    """
    Check whether an IP address is a real public IP.

    Private, loopback, reserved and link-local addresses
    are ignored because they cannot represent a public
    attacker location.
    """

    try:

        address = ipaddress.ip_address(ip)

        return not (
            address.is_private
            or address.is_loopback
            or address.is_reserved
            or address.is_link_local
        )

    except ValueError:

        return False


def geolocate_ip(ip):
    """
    Resolve an attacker IP to approximate geographic
    information.

    Uses ip-api.com.

    No API key is required for the HTTP endpoint.

    Results are cached for 24 hours.
    """

    # -----------------------------------------------------
    # Ignore invalid/private IP addresses
    # -----------------------------------------------------

    if not is_public_ip(ip):
        return None

    # -----------------------------------------------------
    # Check cache
    # -----------------------------------------------------

    cached = GEO_CACHE.get(ip)

    if cached:

        cached_time = cached.get("_cached_at", 0)

        if time.time() - cached_time < GEO_CACHE_TTL:

            return cached

    # -----------------------------------------------------
    # Ask the geolocation service
    # -----------------------------------------------------

    try:

        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={
                "fields": (
                    "status,message,country,countryCode,"
                    "regionName,city,lat,lon,isp,org,as"
                )
            },
            timeout=5,
        )

        if response.status_code != 200:

            print(
                f"[Attack Map] Geolocation HTTP error "
                f"for {ip}: {response.status_code}"
            )

            return None

        data = response.json()

        # -------------------------------------------------
        # Geolocation service rejected the IP
        # -------------------------------------------------

        if data.get("status") != "success":

            print(
                f"[Attack Map] Could not geolocate {ip}: "
                f"{data.get('message', 'Unknown error')}"
            )

            return None

        # -------------------------------------------------
        # Store useful information
        # -------------------------------------------------

        result = {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "_cached_at": time.time(),
        }

        # -------------------------------------------------
        # Save to cache
        # -------------------------------------------------

        GEO_CACHE[ip] = result

        return result

    except requests.RequestException as error:

        print(
            f"[Attack Map] Geolocation request failed "
            f"for {ip}: {error}"
        )

        return None

    except Exception as error:

        print(
            f"[Attack Map] Unexpected geolocation error "
            f"for {ip}: {error}"
        )

        return None


# =========================================================
# HOME
# =========================================================

@app.get("/")
def home():

    return {
        "name": "BaitTrace",
        "status": "online",
        "message": "BaitTrace Honeypot API is running",
    }


# =========================================================
# STATS
# =========================================================

@app.get("/api/stats")
def get_stats():

    events = read_events()

    summary = summarize_events(events)

    return summary


# =========================================================
# RISK CALCULATION
# =========================================================

def calculate_attacker_risk(events):
    """
    Calculate the risk score for one attacker
    based on the events generated by Cowrie.
    """

    score = 0

    for event in events:

        event_id = event.get("eventid", "")

        # -------------------------------------------------
        # Failed login attempt
        # -------------------------------------------------

        if event_id == "cowrie.login.failed":

            score += 10

        # -------------------------------------------------
        # Successful login
        # -------------------------------------------------

        elif event_id == "cowrie.login.success":

            score += 30

        # -------------------------------------------------
        # Command executed
        # -------------------------------------------------

        elif event_id == "cowrie.command.input":

            # Base command score
            score += 15

            command = (
                event.get("input") or ""
            ).lower()

            critical_commands = [
                "rm -rf",
                "mkfs",
                "dd if=",
                "shutdown",
                "reboot",
            ]

            high_commands = [
                "wget",
                "curl",
                "chmod +x",
                "nc ",
                "netcat",
                "bash -i",
                "python -c",
                "perl -e",
            ]

            if any(
                item in command
                for item in critical_commands
            ):

                score += 30

            elif any(
                item in command
                for item in high_commands
            ):

                score += 20

        # -------------------------------------------------
        # Failed command
        # -------------------------------------------------

        elif event_id == "cowrie.command.failed":

            score += 5

        # -------------------------------------------------
        # New SSH session
        # -------------------------------------------------

        elif event_id == "cowrie.session.connect":

            score += 2

    # -----------------------------------------------------
    # Risk level
    # -----------------------------------------------------

    if score >= 70:

        risk_level = "CRITICAL"

    elif score >= 40:

        risk_level = "HIGH"

    elif score >= 20:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    return score, risk_level


# =========================================================
# ATTACKERS
# =========================================================

@app.get("/api/attackers")
def get_attackers():

    events = read_events()

    attackers = {}

    for event in events:

        ip = event.get("src_ip")

        if not ip:
            continue

        # -------------------------------------------------
        # Create attacker
        # -------------------------------------------------

        if ip not in attackers:

            attackers[ip] = {
                "ip": ip,
                "events": 0,
                "logins": 0,
                "successful_logins": 0,
                "commands": 0,
                "failed_commands": 0,
                "first_seen": event.get("timestamp"),
                "last_seen": event.get("timestamp"),
            }

        attacker = attackers[ip]

        # -------------------------------------------------
        # Event count
        # -------------------------------------------------

        attacker["events"] += 1

        # -------------------------------------------------
        # Timestamp
        # -------------------------------------------------

        timestamp = event.get("timestamp")

        if timestamp:

            if not attacker["first_seen"]:

                attacker["first_seen"] = timestamp

            attacker["last_seen"] = timestamp

        # -------------------------------------------------
        # Event type
        # -------------------------------------------------

        event_id = event.get("eventid", "")

        # Failed login
        if event_id == "cowrie.login.failed":

            attacker["logins"] += 1

        # Successful login
        elif event_id == "cowrie.login.success":

            attacker["successful_logins"] += 1

        # Command executed
        elif event_id == "cowrie.command.input":

            attacker["commands"] += 1

        # Failed command
        elif event_id == "cowrie.command.failed":

            attacker["failed_commands"] += 1

    # =====================================================
    # CALCULATE REAL RISK FOR EVERY ATTACKER
    # =====================================================

    attacker_list = []

    for ip, attacker in attackers.items():

        attacker_events = [
            event
            for event in events
            if event.get("src_ip") == ip
        ]

        risk_score, risk_level = calculate_attacker_risk(
            attacker_events
        )

        attacker["risk_score"] = risk_score

        attacker["risk_level"] = risk_level

        attacker_list.append(attacker)

    # -----------------------------------------------------
    # Highest risk first
    # -----------------------------------------------------

    attacker_list.sort(
        key=lambda attacker: attacker["risk_score"],
        reverse=True,
    )

    return attacker_list


# =========================================================
# ATTACK MAP
# =========================================================

@app.get("/api/attack-map")
def get_attack_map():

    events = read_events()

    attackers = {}

    # =====================================================
    # GROUP ALL COWRIE EVENTS BY ATTACKER IP
    # =====================================================

    for event in events:

        ip = event.get("src_ip")

        if not ip:
            continue

        if ip not in attackers:

            attackers[ip] = []

        attackers[ip].append(event)

    # =====================================================
    # CREATE MAP POINTS
    # =====================================================

    map_points = []

    for ip, attacker_events in attackers.items():

        # -------------------------------------------------
        # Calculate the same BaitTrace risk score used by
        # the existing attacker dashboard.
        # -------------------------------------------------

        risk_score, risk_level = calculate_attacker_risk(
            attacker_events
        )

        # -------------------------------------------------
        # Get approximate geographic information.
        # -------------------------------------------------

        location = geolocate_ip(ip)

        # -------------------------------------------------
        # If the IP cannot be geolocated, simply skip it.
        # The attacker still remains visible in the normal
        # Attackers page.
        # -------------------------------------------------

        if not location:

            continue

        lat = location.get("lat")

        lon = location.get("lon")

        if lat is None or lon is None:

            continue

        # -------------------------------------------------
        # Find timestamps
        # -------------------------------------------------

        timestamps = [
            event.get("timestamp")
            for event in attacker_events
            if event.get("timestamp")
        ]

        first_seen = (
            timestamps[0]
            if timestamps
            else None
        )

        last_seen = (
            timestamps[-1]
            if timestamps
            else None
        )

        # -------------------------------------------------
        # Create map point
        # -------------------------------------------------

        map_points.append(
            {
                "ip": ip,

                "lat": lat,

                "lon": lon,

                "country": location.get(
                    "country"
                ),

                "country_code": location.get(
                    "country_code"
                ),

                "region": location.get(
                    "region"
                ),

                "city": location.get(
                    "city"
                ),

                "isp": location.get(
                    "isp"
                ),

                "org": location.get(
                    "org"
                ),

                "asn": location.get(
                    "asn"
                ),

                "risk_score": risk_score,

                "risk_level": risk_level,

                "events": len(attacker_events),

                "first_seen": first_seen,

                "last_seen": last_seen,
            }
        )

    # =====================================================
    # HIGHEST RISK FIRST
    # =====================================================

    map_points.sort(
        key=lambda point: point["risk_score"],
        reverse=True,
    )

    return map_points


# =========================================================
# EVENTS
# =========================================================

@app.get("/api/events")
def get_events():

    events = read_events()

    formatted_events = []

    for event in events:

        event_copy = dict(event)

        # Make sure severity always comes from backend
        event_copy["severity"] = calculate_severity(
            event
        )

        formatted_events.append(event_copy)

    # Newest events first
    formatted_events.reverse()

    return formatted_events


# =========================================================
# COMMANDS
# =========================================================

@app.get("/api/commands")
def get_commands():

    events = read_events()

    commands = []

    for event in events:

        event_id = event.get("eventid", "")

        if event_id == "cowrie.command.input":

            commands.append(
                {
                    "timestamp": event.get(
                        "timestamp"
                    ),

                    "ip": event.get(
                        "src_ip"
                    ),

                    "session": event.get(
                        "session"
                    ),

                    "command": event.get(
                        "input",
                        "",
                    ),

                    "severity": calculate_severity(
                        event
                    ),
                }
            )

    return list(reversed(commands))


# =========================================================
# LOGIN ATTEMPTS
# =========================================================

@app.get("/api/logins")
def get_logins():

    events = read_events()

    logins = []

    for event in events:

        event_id = event.get("eventid", "")

        if event_id in [
            "cowrie.login.failed",
            "cowrie.login.success",
        ]:

            logins.append(
                {
                    "timestamp": event.get(
                        "timestamp"
                    ),

                    "ip": event.get(
                        "src_ip"
                    ),

                    "username": event.get(
                        "username"
                    ),

                    "password": event.get(
                        "password"
                    ),

                    "success": (
                        event_id
                        == "cowrie.login.success"
                    ),

                    "severity": calculate_severity(
                        event
                    ),
                }
            )

    return list(reversed(logins))


# =========================================================
# ATTACKER RISK
# =========================================================

@app.get("/api/attackers/{ip}/risk")
def get_attacker_risk(ip: str):

    events = read_events()

    attacker_events = [
        event
        for event in events
        if event.get("src_ip") == ip
    ]

    score, risk_level = calculate_attacker_risk(
        attacker_events
    )

    return {
        "ip": ip,
        "risk_score": score,
        "risk_level": risk_level,
        "events": len(attacker_events),
    }


# =========================================================
# RAW EVENTS FEED (for the SentinelCore bridge - no SSH needed)
# =========================================================

@app.get("/api/raw-events")
def get_raw_events(since: str = ""):
    """
    Returns raw Cowrie events newer than the given ISO timestamp.
    Used by honeypot_bridge.py (running elsewhere) to pull new real
    attacker events over the internet, since this hosting has no
    terminal/SSH access to read cowrie.json directly.

    Usage: GET /api/raw-events?since=2026-09-22T10:00:00.000000Z
    Leave 'since' empty to get everything (only do this once, for baseline).
    """

    events = read_events()

    if since:
        events = [e for e in events if e.get("timestamp", "") > since]

    # Sort oldest first, so the bridge processes them in order
    events.sort(key=lambda e: e.get("timestamp", ""))

    return events


# =========================================================
# SERVER STATUS
# =========================================================

@app.get("/api/status")
def get_status():

    events = read_events()

    return {
        "system": "BaitTrace",
        "status": "online",
        "total_events": len(events),
        "honeypot": "Cowrie",
        "api": "FastAPI",
    }