import re
import os
import time
import subprocess
import psutil
import glob
from datetime import datetime
from collections import defaultdict

class SuspiciousActivityDetector:
    def __init__(self):
        self.suspicious_process_patterns = [
            re.compile(r'nc\s', re.IGNORECASE),
            re.compile(r'\bnmap\b', re.IGNORECASE),
            re.compile(r'\btcpdump\b', re.IGNORECASE),
            re.compile(r'\bhping\b', re.IGNORECASE),
            re.compile(r'\bwget\b\s.*http', re.IGNORECASE),
            re.compile(r'curl\s.*http', re.IGNORECASE),
            re.compile(r'chmod\s.*777', re.IGNORECASE),
            re.compile(r'/tmp/', re.IGNORECASE),
            re.compile(r'\.exe\b', re.IGNORECASE),
            re.compile(r'\bpython\b.*-c\s', re.IGNORECASE),
        ]
        
        # Precompile log patterns
        self.log_patterns = {
            'CRITICAL': [re.compile(p, re.IGNORECASE) for p in [
                r'panic', r'kernel panic', r'segfault', r'core dumped', r'fatal',
                r'BUG:.*kernel', r'block crash', r'oops', r'unrecoverable error',
                r'critical', r'emergency', r'emerg', r'crit:'
            ]],
            'SECURITY': [re.compile(p, re.IGNORECASE) for p in [
                r'unauthorized', r'permission denied', r'failed password', r'sudo:.*authentication failure',
                r'possible break-in attempt', r'root login attempt', r'security breach',
                r'authentication failure', r'invalid user', r'illegal user', r'failed login',
                r'brute force', r'ssh.*break', r'pam_unix.*authentication failure'
            ]],
            'NETWORK': [re.compile(p, re.IGNORECASE) for p in [
                r'network unreachable', r'disconnected', r'no route to host', r'timeout',
                r'dns lookup failed', r'connection refused', r'dropped connection', r'firewall',
                r'iptables', r'connection reset', r'network.*down', r'interface.*down'
            ]],
            'SYSTEM': [re.compile(p, re.IGNORECASE) for p in [
                r'\[ERROR\]', r'error:', r'failed to', r'daemon.*fail', r'service.*fail',
                r'disk full', r'mount error', r'out of memory', r'systemd.*fail', r'oom-killer',
                r'failed', r'exception', r'traceback', r'errno', r'cannot'
            ]],
            'WARNING': [re.compile(p, re.IGNORECASE) for p in [
                r'\bWARN\b', r'warning:', r'deprecated', r'obsolete', r'denied', r'low memory',
                r'warn:', r'caution', r'alert', r'notice'
            ]]
        }

        self.seen_logs = set()
        self.log_categories = defaultdict(list)
        self.last_full_scan = 0
        self.debug_stats = defaultdict(int)
        self.log_cache = []  # Cache pentru log-urile găsite


    def is_suspicious_process(self, process):
        """Check if a process is suspicious"""
        try:
            cmdline = ' '.join(process.cmdline())
            name = process.name()

            # Check for suspicious patterns in the command line
            for pattern in self.suspicious_process_patterns:
                if pattern.search(cmdline):
                    return True

            # Check for high CPU usage
            if process.cpu_percent() > 95:
                safe = ['chrome', 'firefox', 'python3', 'code', 'top', 'htop', 'stress']
                if name.lower() not in safe:
                    return True

            # Check for processes running from suspicious locations
            try:
                exe_path = process.exe()
                if any(p in exe_path for p in ['/tmp', '/dev/shm', '/var/tmp']):
                    return True
            except:
                pass

            # Check for suspicious process names
            if name.lower() in ['nc', 'ncat', 'telnet', 'ftp', 'socat']:
                return True

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False

        return False

    def _try_access_log_file(self, path):
        """Check if a log file is accessible"""
        try:
            if not os.path.isfile(path):
                return False
            
            # Check if the file is not too large (max 100MB)
            if os.path.getsize(path) > 100 * 1024 * 1024:
                return False
            
            # Check if we have read permissions
            if not os.access(path, os.R_OK):
                return False
                
            return True
        except:
            return False

    def get_log_files(self):
        """Get the list of accessible log files"""
        standard_logs = [
            '/var/log/syslog', '/var/log/auth.log', '/var/log/kern.log',
            '/var/log/dmesg', '/var/log/messages', '/var/log/secure',
            '/var/log/daemon.log', '/var/log/mail.log', '/var/log/cron.log'
        ]
        
        # Look for .log files in /var/log/
        try:
            glob_logs = glob.glob('/var/log/*.log')
            glob_logs.extend(glob.glob('/var/log/*/*.log'))
        except:
            glob_logs = []
        
        # Look for systemd journals (if accessible)
        systemd_logs = []
        try:
            result = subprocess.run(['journalctl', '--list-boots', '-q'], 
                                  capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                systemd_logs.append('journalctl')  # Marker for systemd
        except:
            pass
        
        # Filter only accessible files
        accessible_logs = []
        all_logs = list(set(standard_logs + glob_logs))
        
        for log_file in all_logs:
            if self._try_access_log_file(log_file):
                accessible_logs.append(log_file)
        
        # Add systemd if available
        accessible_logs.extend(systemd_logs)
        
        self.debug_stats['total_log_files'] = len(accessible_logs)
        return accessible_logs

    def _categorize_log_entry(self, line):
        """Categorize a log line"""
        matched = []
        line_lower = line.lower()
        
        for category, patterns in self.log_patterns.items():
            for pattern in patterns:
                if pattern.search(line_lower):
                    matched.append(category)
                    break  # Break after the first match in this category
        
        return matched

    def _scan_single_log(self, log_file):
        """Scan a single log file"""
        results = []
        
        try:
            # Read the last 500 lines
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                # For large files, read only the end
                f.seek(0, 2)  # Go to the end of the file
                file_size = f.tell()
                
                # Read at most the last 100KB for performance
                if file_size > 100 * 1024:  # If file > 100KB
                    f.seek(max(0, file_size - 100 * 1024))  # Read the last 100KB
                else:
                    f.seek(0)
                
                lines = f.readlines()
                
            # Process the last 500 lines
            lines = lines[-500:]
            self.debug_stats[f'lines_read_{os.path.basename(log_file)}'] = len(lines)
            
        except Exception as e:
            self.debug_stats[f'error_{os.path.basename(log_file)}'] = str(e)
            return results

        processed_lines = 0
        for line in lines:
            line = line.strip()
            
            # Skip empty or very short lines
            if not line or len(line) < 10:
                continue
            
            # Avoid duplicates
            if line in self.seen_logs:
                continue
            
            self.seen_logs.add(line)
            processed_lines += 1
            
            # Categorize the line
            categories = self._categorize_log_entry(line)
            
            if categories:
                entry = {
                    'file': os.path.basename(log_file),
                    'content': line[:500],  # Limit the content
                    'timestamp': datetime.now().strftime('%H:%M:%S'),
                    'categories': categories,
                    'raw_line': line
                }
                results.append(entry)
        
        self.debug_stats[f'processed_{os.path.basename(log_file)}'] = processed_lines
        self.debug_stats[f'found_{os.path.basename(log_file)}'] = len(results)
        
        return results

    def _scan_systemd_journal(self):
        """Scan the systemd journal"""
        results = []
        
        try:
            # Read the last 500 entries from the journal
            cmd = ['journalctl', '-n', '500', '--no-pager', '-q']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return results
            
            lines = result.stdout.split('\n')
            self.debug_stats['journalctl_lines'] = len(lines)
            
            for line in lines:
                line = line.strip()
                if not line or len(line) < 10:
                    continue
                
                if line in self.seen_logs:
                    continue
                
                self.seen_logs.add(line)
                categories = self._categorize_log_entry(line)
                
                if categories:
                    entry = {
                        'file': 'journalctl',
                        'content': line[:500],
                        'timestamp': datetime.now().strftime('%H:%M:%S'),
                        'categories': categories,
                        'raw_line': line
                    }
                    results.append(entry)
        
        except Exception as e:
            self.debug_stats['journalctl_error'] = str(e)
        
        return results

    def scan_logs(self, force_full_scan=False):
        """Scanează log-urile păstrând intrările existente"""
        if force_full_scan:
            self.seen_logs.clear()
            self.debug_stats.clear()
            self.last_full_scan = time.time()
            self.log_cache = []  # Reset cache la scanare completă

        self.log_categories.clear()
        new_results = []
        
        # Scanează fișierele de log
        log_files = self.get_log_files()
        
        for log_file in log_files:
            if log_file == 'journalctl':
                results = self._scan_systemd_journal()
            else:
                results = self._scan_single_log(log_file)
            
            for entry in results:
                for category in entry['categories']:
                    self.log_categories[category].append(entry)
            
            new_results.extend(results)

        # Adaugă noile rezultate la cache-ul existent
        all_results = self.log_cache + new_results
        
        # Sortează după prioritate
        def log_sort_key(entry):
            categories = entry['categories']
            priority_order = ['CRITICAL', 'SECURITY', 'NETWORK', 'SYSTEM', 'WARNING']
            for i, priority in enumerate(priority_order):
                if priority in categories:
                    return i
            return 99

        all_results.sort(key=log_sort_key)
        
        # Actualizează cache-ul cu toate intrările
        self.log_cache = all_results[:500]  # Păstrează doar ultimele 500
        
        # Actualizează statisticile
        self.debug_stats['total_entries'] = len(all_results)
        self.debug_stats['returned_entries'] = len(self.log_cache)
        self.debug_stats['cache_size'] = len(self.seen_logs)
        
        return self.log_cache
