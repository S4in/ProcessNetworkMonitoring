import sys
import time
from multiprocessing import Process
from threading import  Thread
from resmonpy.config import Config
from resmonpy.network import NetworkMonitor
from resmonpy.process import ProcessMonitor, get_pid
from resmonpy.utils import is_admin, parse_arguments, verify_processes


def main():

    # system info
    if not is_admin():
        print("This script requires administrator privileges. Please run as an administrator.")
        sys.exit(1)

    args = parse_arguments()
    config = Config(directory=args.directory)
    process_names = verify_processes(args.processes)
    process_dict = get_pid(process_names)
    if not process_dict:
        print("No processes were found")
        sys.exit(1)

    if args.monitor == 'network':
        network_monitor = NetworkMonitor(process_dict=process_dict, interval=args.interval, config=config)
        network_monitor.start_monitoring()

    elif args.monitor == 'process':
        process_monitor = ProcessMonitor(process_dict=process_dict, interval=args.interval, config=config)
        process_monitor.start_monitoring()

    elif args.monitor == 'all':
        process_monitor = ProcessMonitor(process_dict=process_dict, interval=args.interval, config=config)
        network_monitor = NetworkMonitor(process_dict=process_dict, interval=args.interval, config=config)

        process_monitor_thread = Thread(target=process_monitor.start_monitoring)
        network_monitor_thread = Thread(target=network_monitor.start_monitoring)
        try:

            process_monitor_thread.start()
            network_monitor_thread.start()

            while process_monitor_thread.is_alive() and network_monitor_thread.is_alive():
                time.sleep(0.1)

        except KeyboardInterrupt:
            print("Monitoring aborted by user")
            process_monitor.stop()
            network_monitor.stop()
            process_monitor_thread.join()
            network_monitor_thread.join()


if __name__ == "__main__":
    main()
