import sys
import os
import psutil
import subprocess
import threading
from PyQt6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QMessageBox
)
from PyQt6.QtCore import pyqtSignal, QObject, QTimer

class Scanner(QObject):
    log_signal = pyqtSignal(str)
    done_signal = pyqtSignal(list)

    def __init__(self):
        super().__init__()

    def scan(self):
        suspicious = []
        keywords = ['keylog', 'pynput', 'keyboard', 'hook', 'record_keys', 'logger', 'input']

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
            try:
                cmdline = proc.info.get('cmdline') or []
                exe_path = proc.info.get('exe') or ''
                name = proc.info.get('name') or ''
                cmd_str = ' '.join(cmdline).lower()

                if any(k in cmd_str for k in keywords) or any(k in exe_path.lower() for k in keywords) or any(k in name.lower() for k in keywords):
                    msg = f"[ALERT] Suspicious Process:\n  PID: {proc.pid}\n  Name: {name}\n  Executable: {exe_path}\n  Cmd: {cmd_str}\n{'-'*60}"
                    self.log_signal.emit(msg)
                    suspicious.append(proc)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        if not suspicious:
            self.log_signal.emit("[SAFE] No suspicious keyloggers detected.")

        self.done_signal.emit(suspicious)


class AntiKeylogger(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Anti-Keylogger")
        self.setGeometry(300, 300, 700, 500)

        self.suspicious_processes = []

        layout = QVBoxLayout()
        self.result_box = QTextEdit()
        self.result_box.setReadOnly(True)
        layout.addWidget(self.result_box)

        self.scan_button = QPushButton("Scan for Keyloggers")
        self.scan_button.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_button)

        self.kill_button = QPushButton("Kill Suspicious Processes")
        self.kill_button.clicked.connect(self.kill_processes)
        layout.addWidget(self.kill_button)

        self.setLayout(layout)

        self.scanner = Scanner()
        self.scanner.log_signal.connect(self.update_log)
        self.scanner.done_signal.connect(self.finish_scan)

    def start_scan(self):
        self.scan_button.setEnabled(False)
        self.result_box.clear()
        thread = threading.Thread(target=self.scanner.scan)
        thread.start()

    def update_log(self, text):
        self.result_box.append(text)

    def finish_scan(self, processes):
        self.suspicious_processes = processes
        self.scan_button.setEnabled(True)

    def kill_processes(self):
        if not self.suspicious_processes:
            QMessageBox.information(self, "No Threats", "No suspicious processes found.")
            return

        for proc in self.suspicious_processes:
            try:
                proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        QMessageBox.information(self, "Killed", "Suspicious processes terminated.")
        self.result_box.append("[INFO] Terminated suspicious processes.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = AntiKeylogger()
    win.show()
    sys.exit(app.exec())
