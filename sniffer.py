import threading
from scapy.all import sniff
from packet_analyzer import extract_packet_info
from detectors import analyze
import config


class PacketSniffer:
    def __init__(self, packet_queue, alert_queue):
        self.packet_queue = packet_queue
        self.alert_queue = alert_queue
        self.thread = None
        self.running = False

    def _sniff_loop(self):
        sniff(
            iface=config.INTERFACE,
            prn=self._handle_packet,
            store=False,
            stop_filter=lambda packet: not self.running
        )

    def _handle_packet(self, packet):
        packet_info = extract_packet_info(packet)

        if packet_info is None:
            return

        self.packet_queue.put(packet_info)

        alerts = analyze(packet_info)

        for alert in alerts:
            self.alert_queue.put(alert)

    def start(self):
        if self.running:
            return

        self.running = True

        self.thread = threading.Thread(
            target=self._sniff_loop,
            daemon=True
        )

        self.thread.start()

    def stop(self):
        self.running = False
