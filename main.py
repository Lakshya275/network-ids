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
        self.root.geometry("900x500")

        # Shared queue: sniffer thread puts packets here, GUI reads from it
        self.packet_queue = queue.Queue()
        self.sniffer = PacketSniffer(self.packet_queue)

        self._build_widgets()
        self._poll_queue()

    def _build_widgets(self):
        control_frame = tk.Frame(self.root)
        control_frame.pack(fill="x", padx=10, pady=10)

        self.start_btn = tk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring, bg="#4CAF50", fg="white")
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(control_frame, text="Stop Monitoring", command=self.stop_monitoring, bg="#f44336", fg="white", state="disabled")
        self.stop_btn.pack(side="left", padx=5)

        self.status_label = tk.Label(control_frame, text="Status: Stopped", font=("Arial", 10, "bold"))
        self.status_label.pack(side="left", padx=20)

        self.packet_count_label = tk.Label(control_frame, text="Packets: 0")
        self.packet_count_label.pack(side="right", padx=5)

        columns = ("time", "src_ip", "dst_ip", "protocol", "src_port", "dst_port", "flags", "length")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=20)

        headings = {
            "time": "Time",
            "src_ip": "Source IP",
            "dst_ip": "Destination IP",
            "protocol": "Protocol",
            "src_port": "Src Port",
            "dst_port": "Dst Port",
            "flags": "Flags",
            "length": "Length",
        }
        for col, text in headings.items():
            self.tree.heading(col, text=text)
            self.tree.column(col, width=100, anchor="center")

        self.tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self.packet_count = 0

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

    def _poll_queue(self):
        try:
            while True:
                info = self.packet_queue.get_nowait()
                self._add_packet_row(info)
        except queue.Empty:
            pass

        self.root.after(200, self._poll_queue)

    def _add_packet_row(self, info):
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")

        self.tree.insert("", "end", values=(
            timestamp,
            info["src_ip"],
            info["dst_ip"],
            info["protocol"],
            info["src_port"],
            info["dst_port"],
            info["flags"],
            info["length"],
        ))

        children = self.tree.get_children()
        if children:
            self.tree.see(children[-1])

        if len(children) > 500:
            self.tree.delete(children[0])

        self.packet_count += 1
        self.packet_count_label.config(text=f"Packets: {self.packet_count}")


if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()