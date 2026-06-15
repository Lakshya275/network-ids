# packet_analyzer.py

from scapy.all import IP, TCP, UDP


def extract_packet_info(packet):
   

    # Ignore packets that donot in use
    if not packet.haslayer(IP):
        return None

    # Extract packet information
    packet_info = {
        "src_ip": packet[IP].src,
        "dst_ip": packet[IP].dst,
        "protocol": "OTHER",
        "src_port": "",
        "dst_port": "",
        "flags": "",
        "length": len(packet)
    }

    # check TCP
    if packet.haslayer(TCP):
        packet_info["protocol"] = "TCP"
        packet_info["src_port"] = packet[TCP].sport
        packet_info["dst_port"] = packet[TCP].dport
        packet_info["flags"] = str(packet[TCP].flags)

    # check UDP

    elif packet.haslayer(UDP):
        packet_info["protocol"] = "UDP"
        packet_info["src_port"] = packet[UDP].sport
        packet_info["dst_port"] = packet[UDP].dport

    return packet_info