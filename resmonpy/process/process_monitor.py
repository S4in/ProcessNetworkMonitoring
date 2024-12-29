import os
import sys
import csv

import time
import psutil
from datetime import datetime
from threading import Thread, Event, Lock
from resmonpy.utils import generate_timestamped_filename
from resmonpy.process import get_pid


class ProcessMonitor:
    def __init__(self, process_dict, interval, config=None):
        if config is None:
            print("A valid Config instance must be provided.")
            sys.exit(1)

        self.config = config
        self.output_file = self.init_output_file()

        self.process_dict = process_dict
        self.interval = interval
        self.is_running = True

    def init_output_file(self):
        if self.config.data_format == 'csv':
            csv_file = generate_timestamped_filename("process", self.config.data_format)
            csv_path = os.path.join(self.config.directory, csv_file)
            with open(file=csv_path, mode='w+', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(['Time', 'Process Name', 'PID', 'CPU %', 'Memory %', 'Memory'])

            return csv_path

    def get_resource_usage(self):

        for pid, process_name in self.process_dict.items():

            if psutil.pid_exists(pid):
                process = psutil.Process(pid)
                self.save_to_csv(process_name, pid, process.cpu_percent(),
                                 process.memory_percent(), process.memory_info().rss / (1024 * 1024))

    def save_to_csv(self, process_name, pid, cpu_percent, memory_percent, memory):
        with open(file=self.output_file, mode='a+', newline='') as csv_file:
            writer = csv.writer(csv_file)
            now = datetime.now()
            dt_string = now.strftime("%d/%m/%Y %H:%M:%S")
            cpu_percent = round(cpu_percent, 2)
            memory_percent = round(memory_percent, 2)
            memory = round(memory, 2)
            writer.writerow([dt_string, process_name, pid, cpu_percent, memory_percent, memory])

    def update(self):
        self.process_dict = get_pid(list(self.process_dict.values()))
        if not self.process_dict:
            self.stop()

    def monitor_usage(self):
        while self.is_running:
            self.get_resource_usage()
            time.sleep(self.interval)
            self.update()

    def start_monitoring(self):

        try:
            self.monitor_usage()

        except KeyboardInterrupt:
            self.stop()
            print("Process monitoring aborted by user")

    def stop(self):
        self.is_running = False
