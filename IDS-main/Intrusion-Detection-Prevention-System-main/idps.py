import os
import socket
import time
import threading
import fnmatch
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileDeletedEvent, FileMovedEvent, FileModifiedEvent
import tkinter as tk
from tkinter import scrolledtext
from monitor import monitor_network_connections, monitor_system_processes
from detector import AdvancedAnomalyDetector
import requests
import json

def send_discord_alert(message, webhook_url):
    payload = {
        "content": message
    }

    headers = {
        "Content-Type": "application/json"
    }

    response = requests.post(webhook_url, data=json.dumps(payload), headers=headers)

    # ตรวจสอบการตอบกลับจาก Discord
    if response.status_code == 204:
        print("Alert sent to Discord successfully!")
    else:
        print(f"Failed to send alert. Status Code: {response.status_code}, Response: {response.text}")


class IDPSEventHandler(FileSystemEventHandler):
    def __init__(self, ignore_patterns=None, anomaly_detector=None, gui_app=None):
        super().__init__()
        self.ignore_patterns = ignore_patterns or []
        self.anomaly_detector = anomaly_detector
        self.gui_app = gui_app

    def _get_event_type(self, event):
        if isinstance(event, FileCreatedEvent):
            return 0
        elif isinstance(event, FileDeletedEvent):
            return 1
        elif isinstance(event, FileMovedEvent):
            return 2
        elif isinstance(event, FileModifiedEvent):
            return 3
        else:
            return -1

    def _get_event_vector(self, event):
        event_type = self._get_event_type(event)
        if event_type == -1:
            return None
        file_size = 0
        if os.path.exists(event.src_path):
            file_size = os.path.getsize(event.src_path)
        return [event_type, file_size]

    def should_ignore(self, path):
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False
    
    def log_event(self, event_type, path):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        with open("./logs/file_log.txt", "a") as log_file:
            log_file.write(f"{timestamp} - {event_type} - {path}\n")

    def on_created(self, event):
        if self.should_ignore(event.src_path):
            return
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)

        alert_message = f"Alert!! {event.src_path} created at {timestamp} from IP {ip_address}."

        # ส่งการแจ้งเตือนผ่าน Discord
        webhook_url = "https://discord.com/api/webhooks/1307726871160422420/-Vrojq8zPXJ3d3FPPvPvy3Rh_caxygsH3lNFaFTL2DnvRFW_dF_pcYmvI0NJ09YXSmiY"  # ใช้ URL ที่ถูกต้อง
        send_discord_alert(alert_message, webhook_url)
        
    
        self.gui_app.update_log(alert_message)
        self.log_event(f"created at {timestamp} from IP {ip_address}", event.src_path)
       

    def on_deleted(self, event):
        if self.should_ignore(event.src_path):
            return
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        alert_message = f"Alert!! {event.src_path} deleted at {timestamp} from IP {ip_address}."

        # ส่งการแจ้งเตือนผ่าน Discord
        webhook_url = "https://discord.com/api/webhooks/1307726871160422420/-Vrojq8zPXJ3d3FPPvPvy3Rh_caxygsH3lNFaFTL2DnvRFW_dF_pcYmvI0NJ09YXSmiY"  # ใช้ URL ที่ถูกต้อง
        send_discord_alert(alert_message, webhook_url)
        
    
        self.gui_app.update_log(alert_message)
        self.log_event(f"deleted at {timestamp} from IP {ip_address}", event.src_path)
      



    def on_moved(self, event):
        if self.should_ignore(event.src_path) and self.should_ignore(event.dest_path):
            return
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)
        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)

        alert_message = f"Alert!! {event.src_path} moved to {timestamp} {event.dest_path} from IP {ip_address}."
        self.gui_app.update_log(alert_message)
        self.log_event("moved", f"{timestamp} {event.src_path} -> {event.dest_path} from IP {ip_address}")

        # ส่งการแจ้งเตือนผ่าน Discord
        webhook_url = "https://discord.com/api/webhooks/1307726871160422420/-Vrojq8zPXJ3d3FPPvPvy3Rh_caxygsH3lNFaFTL2DnvRFW_dF_pcYmvI0NJ09YXSmiY"  # ใช้ URL ที่ถูกต้อง
        send_discord_alert(alert_message, webhook_url)

    def on_modified(self, event):
        if self.should_ignore(event.src_path):
            return
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

        hostname = socket.gethostname()
        ip_address = socket.gethostbyname(hostname)

        feature_vector = self._get_event_vector(event)
        if feature_vector is not None:
            self.anomaly_detector.add_event(feature_vector)

        alert_message = f"Alert!! {event.src_path} modified at {timestamp} from IP {ip_address}."
        self.gui_app.update_log(alert_message)
        self.log_event(f"modified at {timestamp} from IP {ip_address}", event.src_path)

        # ส่งการแจ้งเตือนผ่าน Discord
        webhook_url = "https://discord.com/api/webhooks/1307726871160422420/-Vrojq8zPXJ3d3FPPvPvy3Rh_caxygsH3lNFaFTL2DnvRFW_dF_pcYmvI0NJ09YXSmiY"  # ใช้ URL ที่ถูกต้อง
        send_discord_alert(alert_message, webhook_url)


class IDSApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced IDPS Monitor")

        self.textbox = scrolledtext.ScrolledText(self.root, width=100, height=30)
        self.textbox.pack(padx=10, pady=10)
        self.textbox.insert(tk.END, "IDPS Log:\n")

    def update_log(self, message):
        self.textbox.insert(tk.END, f"{message}\n")
        self.textbox.yview(tk.END)


def main():
    root = tk.Tk()
    app = IDSApp(root)
    anomaly_detector = AdvancedAnomalyDetector(threshold=10, time_window=60)
    event_handler = IDPSEventHandler(ignore_patterns=["*.tmp", "*.log"], anomaly_detector=anomaly_detector, gui_app=app)

    observer = Observer()
    paths = ["C:/Users/Maitvplay/Desktop/TestNew"]
    for path in paths:
        observer.schedule(event_handler, path, recursive=True)

    observer.start()

    # Start monitoring network and system processes in separate threads
    network_monitor_thread = threading.Thread(target=monitor_network_connections)
    network_monitor_thread.daemon = True
    network_monitor_thread.start()

    process_monitor_thread = threading.Thread(target=monitor_system_processes)
    process_monitor_thread.daemon = True
    process_monitor_thread.start()

    try:
        root.mainloop()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
    network_monitor_thread.join()
    process_monitor_thread.join()


if __name__ == "__main__":
    main()

