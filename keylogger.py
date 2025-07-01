#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Secure System Monitor - Cross-platform security monitoring tool
For authorized security research and defensive monitoring only
"""

import os
import sys
import time
import json
import hashlib
import base64
import logging
import threading
from datetime import datetime
from pathlib import Path
import platform

# Security imports
try:
    import psutil  # For cross-platform system monitoring
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
DEFAULT_LOG_RETENTION_DAYS = 7
SECURE_LOG_DIR = "SecureSystemLogs"

class SecureConfig:
    """Secure configuration management with proper encryption"""
    def __init__(self):
        self._config = {
            'monitoring': {
                'max_log_size': DEFAULT_MAX_LOG_SIZE,
                'encryption': {
                    'enabled': CRYPTO_AVAILABLE,
                    'algorithm': 'AES-256-GCM' if CRYPTO_AVAILABLE else None,
                    'key_rotation': 86400  # 24 hours
                },
                'log_retention': DEFAULT_LOG_RETENTION_DAYS
            }
        }
        self._key = self._derive_key() if CRYPTO_AVAILABLE else None

    def _derive_key(self):
        """Securely derive encryption key using PBKDF2"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(self._system_fingerprint().encode())

    def _system_fingerprint(self):
        """Generate anonymous system identifier"""
        safe_attrs = [
            platform.machine(),
            str(os.cpu_count()),
            hashlib.sha256(platform.node().encode()).hexdigest()[:8]
        ]
        return ':'.join(safe_attrs)

    def get(self, key, default=None):
        """Get configuration value safely"""
        keys = key.split('.')
        val = self._config
        try:
            for k in keys:
                val = val[k]
            return val
        except (KeyError, TypeError):
            return default

class SecureCrypto:
    """Modern cryptographic operations with safe defaults"""
    def __init__(self, config):
        self.config = config
        self._key = config._key
        self._rotation_time = time.time()

    def encrypt(self, data):
        """Authenticated encryption with automatic key rotation"""
        if not isinstance(data, bytes):
            data = str(data).encode('utf-8')

        if not CRYPTO_AVAILABLE or not self._key:
            return data  # Fallback to plaintext if crypto unavailable

        self._rotate_key_if_needed()

        iv = os.urandom(12)
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return iv + encryptor.tag + ciphertext

    def _rotate_key_if_needed(self):
        """Rotate encryption key if rotation period has elapsed"""
        if time.time() - self._rotation_time > self.config.get('monitoring.encryption.key_rotation'):
            self._key = self.config._derive_key()
            self._rotation_time = time.time()

    def decrypt(self, data):
        """Authenticated decryption with integrity checking"""
        if not CRYPTO_AVAILABLE or not self._key:
            return data

        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        cipher = Cipher(
            algorithms.AES(self._key),
            modes.GCM(iv, tag),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class ActivityLogger:
    """Secure activity logging with encryption and rotation"""
    def __init__(self, config, crypto):
        self.config = config
        self.crypto = crypto
        self._buffer = []
        self._lock = threading.Lock()
        self._log_file = self._init_log_file()

    def _init_log_file(self):
        """Initialize secure log directory and file"""
        log_dir = Path.home() / SECURE_LOG_DIR
        log_dir.mkdir(mode=0o700, exist_ok=True)
        return log_dir / 'activity.log'

    def log(self, event_type, data):
        """Thread-safe logging with automatic encryption"""
        with self._lock:
            event = {
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'type': event_type,
                'data': data
            }
            self._buffer.append(event)
            
            if len(self._buffer) >= self.config.get('monitoring.max_log_size', DEFAULT_MAX_LOG_SIZE):
                self._flush_buffer()

    def _flush_buffer(self):
        """Flush logs to disk with encryption and rotation"""
        if not self._buffer:
            return
            
        try:
            if self._needs_rotation():
                self._rotate_logs()

            with open(self._log_file, 'ab') as f:
                encrypted = self.crypto.encrypt(json.dumps(self._buffer).encode())
                f.write(encrypted + b'\n')
            self._buffer = []
        except Exception as e:
            logging.error("Log write failed: %s", str(e), exc_info=True)

    def _needs_rotation(self):
        """Check if log rotation is needed"""
        return self._log_file.exists() and \
               self._log_file.stat().st_size > self.config.get('monitoring.max_log_size', DEFAULT_MAX_LOG_SIZE)

    def _rotate_logs(self):
        """Rotate log files with secure naming and permissions"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        rotated_file = self._log_file.with_name(f"{self._log_file.name}.{timestamp}")
        self._log_file.rename(rotated_file)
        rotated_file.chmod(0o600)
        self._clean_old_logs()

    def _clean_old_logs(self):
        """Remove logs older than retention period"""
        cutoff = time.time() - self.config.get('monitoring.log_retention', DEFAULT_LOG_RETENTION_DAYS) * 86400
        log_dir = self._log_file.parent
        
        for log_file in log_dir.glob(f"{self._log_file.name}.*"):
            if log_file.stat().st_mtime < cutoff:
                try:
                    log_file.unlink()
                except Exception as e:
                    logging.warning("Failed to remove old log %s: %s", log_file, str(e))

class SystemMonitor:
    """Cross-platform system monitoring"""
    def __init__(self):
        self.config = SecureConfig()
        self.crypto = SecureCrypto(self.config) if CRYPTO_AVAILABLE else None
        self.logger = ActivityLogger(self.config, self.crypto)
        self._running = False

    def start(self):
        """Start monitoring with proper initialization"""
        self._running = True
        self.logger.log('startup', {
            'pid': os.getpid(),
            'system': self.config._system_fingerprint(),
            'platform': platform.platform()
        })

        # Start monitoring threads
        threading.Thread(target=self._monitor_system, daemon=True).start()
        threading.Thread(target=self._periodic_tasks, daemon=True).start()

        # Main loop
        while self._running:
            time.sleep(1)

    def stop(self):
        """Stop monitoring with proper cleanup"""
        self._running = False
        self.logger.log('shutdown', {})
        self.logger._flush_buffer()

    def _monitor_system(self):
        """Main monitoring loop with safe error handling"""
        while self._running:
            try:
                self._check_resources()
                self._check_network()
                self._check_integrity()
                time.sleep(60)
            except Exception as e:
                self.logger.log('monitor_error', {
                    'error': str(e),
                    'type': type(e).__name__
                })
                time.sleep(10)

    def _check_resources(self):
        """Monitor system resources using psutil or fallbacks"""
        if PSUTIL_AVAILABLE:
            self.logger.log('system_resources', {
                'cpu': psutil.cpu_percent(interval=1),
                'memory': psutil.virtual_memory().percent,
                'disks': {d.mountpoint: psutil.disk_usage(d.mountpoint).percent 
                         for d in psutil.disk_partitions()}
            })

    def _check_network(self):
        """Cross-platform network monitoring"""
        if PSUTIL_AVAILABLE:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                connections.append({
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': str(conn.laddr),
                    'raddr': str(conn.raddr) if conn.raddr else None,
                    'status': conn.status
                })
            self.logger.log('network_connections', {'connections': connections})

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
                Path(os.environ.get('ProgramData')) / 'Microsoft' / 'Windows' / 'Start Menu' / 'Programs' / 'Startup'
            ])
        else:
            system_files.extend([
                Path('/etc/passwd'),
                Path('/etc/shadow'),
                Path('/etc/hosts'),
                Path.home() / '.ssh' / 'authorized_keys'
            ])
        return [f for f in system_files if f.is_file()]

    def _file_hash(self, path):
        """Calculate secure file hash"""
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            while chunk := f.read(4096):
                h.update(chunk)
        return h.hexdigest()

    def _periodic_tasks(self):
        """Handle periodic maintenance tasks"""
        while self._running:
            try:
                self.logger._flush_buffer()
                if CRYPTO_AVAILABLE and self.crypto:
                    self.crypto._rotate_key_if_needed()
                time.sleep(3600)
            except Exception as e:
                self.logger.log('periodic_task_error', {
                    'error': str(e),
                    'type': type(e).__name__
                })
                time.sleep(60)

def main():
    """Main entry point with proper initialization"""
    # Configure secure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(Path.home() / f'{SECURE_LOG_DIR}.log')
        ]
    )
    
    # Security checks
    if os.getuid() == 0:
        logging.error("Should not be run as root!")
        sys.exit(1)

    if not PSUTIL_AVAILABLE:
        logging.warning("psutil not available - reduced functionality")

    monitor = SystemMonitor()
    try:
        monitor.start()
    except KeyboardInterrupt:
        monitor.stop()
    except Exception as e:
        logging.critical("Fatal error: %s", str(e), exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()