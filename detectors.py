import time
from collections import defaultdict
import config

port_activity = defaultdict(lambda: defaultdict(list))
syn_activity = defaultdict(list)
already_alerted = set()


def clean_old_entries(timestamps, window):
    cutoff = time.time() - window
    return [t for t in timestamps if t > cutoff]


def detect_port_scan(info):
    src = info["src_ip"]
    dst_port = info["dst_port"]

    if dst_port == "":
        return

    now = time.time()
    port_activity[src][dst_port].append(now)
    port_activity[src][dst_port] = clean_old_entries(
        port_activity[src][dst_port],
        config.TIME_WINDOW
    )

    recent_ports = [p for p, times in port_activity[src].items() if times]

    if len(recent_ports) > config.PORT_SCAN_THRESHOLD:
        key = f"scan_{src}"
        if key not in already_alerted:
            already_alerted.add(key)
            return (
                f"Possible PORT SCAN from {src} — "
                f"{len(recent_ports)} ports contacted in "
                f"{config.TIME_WINDOW}s"
            )
    return None


def detect_brute_force(info):
    src = info["src_ip"]
    dst_port = info["dst_port"]

    if dst_port not in config.SENSITIVE_PORTS:
        return None

    now = time.time()
    port_activity[src][dst_port].append(now)
    port_activity[src][dst_port] = clean_old_entries(
        port_activity[src][dst_port],
        config.TIME_WINDOW
    )

    count = len(port_activity[src][dst_port])

    if count > config.BRUTE_FORCE_THRESHOLD:
        key = f"brute_{src}_{dst_port}"
        if key not in already_alerted:
            already_alerted.add(key)
            return (
                f"Possible BRUTE FORCE from {src} on port {dst_port} — "
                f"{count} attempts in {config.TIME_WINDOW}s"
            )
    return None


def detect_syn_flood(info):
    if info["protocol"] != "TCP":
        return None

    if "S" not in info["flags"]:
        return None

    src = info["src_ip"]
    now = time.time()

    syn_activity[src].append(now)
    syn_activity[src] = clean_old_entries(
        syn_activity[src],
        config.TIME_WINDOW
    )

    count = len(syn_activity[src])

    if count > config.SYN_FLOOD_THRESHOLD:
        key = f"synflood_{src}"
        if key not in already_alerted:
            already_alerted.add(key)
            return (
                f"Possible SYN FLOOD from {src} — "
                f"{count} SYN packets in {config.TIME_WINDOW}s"
            )
    return None


def analyze(info):
    alerts = []

    for detector in (
        detect_port_scan,
        detect_brute_force,
        detect_syn_flood
    ):
        result = detector(info)
        if result:
            alerts.append(result)

    return alerts
