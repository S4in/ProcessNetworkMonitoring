import os
import sys
import csv
import json
import time
import psutil
from threading import Thread, Event, Lock
from datetime import datetime
from scapy.all import sniff
from scapy.layers.inet import TCP, UDP
from resmonpy.utils import generate_timestamped_filename
from resmonpy.process import get_pid


class NetworkMonitor:
    def __init__(self, process_dict, interval, config=None):
        if config is None:
            print("A valid Config instance must be provided.")
            sys.exit(1)

        self.config = config
        self.process_dict = process_dict
        self.interval = interval
        self.connection_dict = self.get_connections()

        if not self.connection_dict:
            log_message = (f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - No ports to monitor for the given "
                           f"processes.")
            print(log_message)
            sys.exit(1)
        self.lock = Lock()
        self.event = Event()
        self.output_file = self.init_output_file()

    def init_output_file(self):
        if self.config.data_format == 'csv':
            csv_file = generate_timestamped_filename("network", self.config.data_format)
            csv_path = os.path.join(self.config.directory, csv_file)
            with open(file=csv_path, mode='w+', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Timestamp', 'Process Name', 'PID', 'Port', 'Sent (B/s)', 'Received (B/s)', 'Total ('
                                                                                                             'B/s)'])
            return csv_path

    def get_connections(self):
        conn_dict = {}
        for pid in list(self.process_dict.keys()):
            process = psutil.Process(pid)
            connections = process.connections(kind='inet')
            for conn in connections:
                conn_dict[int(conn.laddr.port)] = {
                    'pid': pid,
                    'process_name': self.process_dict[pid],
                    'sent': 0,
                    'received': 0
                }

        return conn_dict

    def update(self):
        self.process_dict = get_pid(list(self.process_dict.values()))
        if not self.process_dict:
            self.stop()
        self.connection_dict = self.get_connections()

    def packet_callback(self, packet):
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            src_port = None
            dst_port = None
            if packet.haslayer(TCP):
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            elif packet.haslayer(UDP):
                src_port = packet[UDP].sport
                dst_port = packet[UDP].dport

            packet_size = len(packet)

            with self.lock:
                if src_port in self.connection_dict:
                    self.connection_dict[src_port]['sent'] += packet_size
                if dst_port in self.connection_dict:
                    self.connection_dict[dst_port]['received'] += packet_size

    def save_network_usage(self):
        while not self.event.is_set():
            time.sleep(self.interval)
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(self.output_file, mode='a+', newline='') as file:
                writer = csv.writer(file)
                with self.lock:
                    for port, data in self.connection_dict.items():
                        pid = data['pid']
                        process_name = data['process_name']
                        sent_bps = data['sent'] / self.interval
                        received_bps = data['received'] / self.interval
                        total_bps = sent_bps + received_bps
                        writer.writerow([timestamp, pid, process_name, port, f"{sent_bps:.2f}", f"{received_bps:.2f}",
                                         f"{total_bps:.2f}"])
                        data['sent'] = 0
                        data['received'] = 0
                    self.update()

    def start_sniffing(self):
        sniff(filter="tcp or udp", stop_filter=lambda pkt: not self.event.is_set(), prn=self.packet_callback, store=0)

    def run_updates(self):
        while not self.event.is_set():
            time.sleep(self.interval * 10)
            self.update()

    def start_monitoring(self):
        sniffer = Thread(target=self.start_sniffing)
        sniffer.daemon = True
        data_handler = Thread(target=self.save_network_usage)

        try:
            sniffer.start()
            data_handler.start()
            while not self.event.is_set():
                time.sleep(0.1)

        except KeyboardInterrupt:
            self.stop()
            print("Network monitor aborted by user")
            data_handler.join()

    def stop(self):
        self.event.set()
