# config.py

# Network interface to monitor.
# Set to None to automatically select the default interface.
INTERFACE = None

# ---------------- Detection Settings ----------------

# Port Scan Detection
# If one IP contacts more than PORT_SCAN_THRESHOLD different ports
# within TIME_WINDOW seconds, flag it as a port scan.
PORT_SCAN_THRESHOLD = 15
TIME_WINDOW = 10  # seconds

# Brute Force Detection
# If one IP sends more than BRUTE_FORCE_THRESHOLD connection attempts
# to the same sensitive port within TIME_WINDOW seconds, flag it.
BRUTE_FORCE_THRESHOLD = 10

# Common services often targeted by brute-force attacks
SENSITIVE_PORTS = [
    22,    # SSH
    21,    # FTP
    23,    # Telnet
    3389,  # RDP
    3306,  # MySQL
    5900   # VNC
]

# SYN Flood Detection
# If one IP sends more than SYN_FLOOD_THRESHOLD SYN packets
# within TIME_WINDOW seconds, flag it as a possible SYN flood attack.
SYN_FLOOD_THRESHOLD = 50
