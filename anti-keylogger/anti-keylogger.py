import sys
import os
import psutil
import subprocess
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QMessageBox

class AntiKeylogger(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Anti-Keylogger Scanner")
        self.setGeometry(300, 300, 600, 400)

        layout = QVBoxLayout()

        self.scan_button = QPushButton("Scan for Keyloggers")
        self.scan_button.clicked.connect(self.scan_system)
        layout.addWidget(self.scan_button)

        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        layout.addWidget(self.result_box)

        self.kill_button = QPushButton("Kill Suspicious Processes")
        self.kill_button.clicked.connect(self.kill_suspicious_processes)
        layout.addWidget(self.kill_button)

        self.setLayout(layout)

    def scan_system(self):
        self.result_box.clear()
        suspicious_processes = []
        
        # Check running processes for keylogging behavior
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['cmdline']:
                    cmdline_str = ' '.join(proc.info['cmdline']).lower()
                    if any(keyword in cmdline_str for keyword in ['pynput', 'keyboard', 'keylogger']):
                        suspicious_processes.append(proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Check for programs accessing keyboard input
        try:
            output = subprocess.check_output("lsof /dev/input/event*", shell=True, stderr=subprocess.DEVNULL).decode()
            if output:
                self.result_box.append("[ALERT] Suspicious process accessing keyboard input:")
                self.result_box.append(output)
        except subprocess.CalledProcessError:
            self.result_box.append("[INFO] No direct keyboard access detected.")

        if suspicious_processes:
            self.result_box.append("\n[ALERT] Suspicious Keylogger Processes Detected:")
            for proc in suspicious_processes:
                self.result_box.append(f"PID: {proc.info['pid']}, Name: {proc.info['name']}, Cmd: {' '.join(proc.info['cmdline'])}")
        else:
            self.result_box.append("[SAFE] No keyloggers detected!")

    def kill_suspicious_processes(self):
        suspicious_pids = []
        
        # Find processes with keylogging behavior
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                if proc.info['cmdline']:
                    cmdline_str = ' '.join(proc.info['cmdline']).lower()
                    if any(keyword in cmdline_str for keyword in ['pynput', 'keyboard', 'keylogger']):
                        suspicious_pids.append(proc.info['pid'])

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        if suspicious_pids:
            for pid in suspicious_pids:
                os.system(f"kill -9 {pid}")

            QMessageBox.information(self, "Action Completed", "Suspicious keylogger processes have been terminated.")
        else:
            QMessageBox.information(self, "No Threats Found", "No suspicious keyloggers were detected.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = AntiKeylogger()
    window.show()
    sys.exit(app.exec())
