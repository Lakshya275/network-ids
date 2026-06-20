# main.py
import tkinter as tk
from tkinter import ttk
import queue
import datetime
from sniffer import PacketSniffer


class App:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Monitor")
        self.root.geometry("1000x650")

        self.packet_queue = queue.Queue()
        self.alert_queue = queue.Queue()
        self.sniffer = PacketSniffer(self.packet_queue, self.alert_queue)

        self.packet_count = 0
        self.alert_count = 0

        self._build_widgets()
        self._poll_queues()

    def _build_widgets(self):
        # --- Top control bar ---
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill="x", padx=10, pady=10)

        self.start_btn = tk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring, bg="#4CAF50", fg="white")
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, bg="#f44336", fg="white", state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.status_label = tk.Label(control_frame, text="Status: Stopped", font=("Arial", 10, "bold"))
        self.status_label.pack(side="left", padx=20)

        self.packet_count_label = tk.Label(control_frame, text="Packets: 0")
        self.packet_count_label.pack(side="right", padx=10)

        self.alert_count_label = tk.Label(control_frame, text="Alerts: 0", fg="red", font=("Arial", 10, "bold"))
        self.alert_count_label.pack(side="right", padx=10)

        # --- Packet table ---
        packet_label = tk.Label(self.root, text="Live Packets", font=("Arial", 10, "bold"))
        packet_label.pack(anchor="w", padx=10)

        columns = ("time", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "flags", "length")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=12)

        headings = {
            "time": "Time", "src_ip": "Source IP", "dst_ip": "Destination IP",
            "protocol": "Protocol", "src_port": "Src Port", "dst_port": "Dst Port",
            "flags": "Flags", "length": "Length",
        }
        for col, text in headings.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=100, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        # --- Alerts panel ---
        alert_label = tk.Label(self.root, text="Alerts", font=("Arial", 10, "bold"), fg="red")
        alert_label.pack(anchor="w", padx=10)

        alert_frame = tk.Frame(self.root)
        alert_frame.pack(fill="both", expand=False, padx=10, pady=(0, 10))

        self.alert_listbox = tk.Listbox(alert_frame, height=8, bg="#fff3f3", fg="#b30000", font=("Consolas", 9))
        self.alert_listbox.pack(side="left", fill="both", expand=True)

        scrollbar = tk.Scrollbar(alert_frame, command=self.alert_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.alert_listbox.config(yscrollcommand=scrollbar.set)

    def start_monitoring(self):
        self.sniffer.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_label.config(text="Status: Running", fg="green")

    def stop_monitoring(self):
        self.sniffer.stop()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_label.config(text="Status: Stopped", fg="black")

    def _poll_queues(self):
        # Drain packet queue
        try:
            while True:
                info = self.packet_queue.get_nowait()
                self._add_packet_row(info)
        except queue.Empty:
            pass

        # Drain alert queue
        try:
            while True:
                alert_message = self.alert_queue.get_nowait()
                self._add_alert(alert_message)
        except queue.Empty:
            pass

        self.root.after(200, self._poll_queues)

    def _add_packet_row(self, info):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.tree.insert("", "end", values=(
            timestamp, info["src_ip"], info["dst_ip"], info["protocol"],
            info["src_port"], info["dst_port"], info["flags"], info["length"],
        ))

        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])
        if len(children) > 500:
            self.tree.delete(children[0])

        self.packet_count += 1
        self.packet_count_label.config(text=f"Packets: {self.packet_count}")

    def _add_alert(self, message):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        self.alert_listbox.insert(0, f"[{timestamp}] {message}")  # newest on top
        self.alert_count += 1
        self.alert_count_label.config(text=f"Alerts: {self.alert_count}")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()
