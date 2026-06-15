# sniffer.py

import threading
from scapy.all import sniff
from packet_analyzer import extract_packet_info
import config


class PacketSniffer:
    
    def __init__(self, output_queue):
        # Queue used to send packet data to the GUI
        self.output_queue = output_queue

        # Thread responsible for packet capturing
        self.thread = None

        # Indicates whether packet sniffing is active
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

        if packet_info:
            self.output_queue.put(packet_info)

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