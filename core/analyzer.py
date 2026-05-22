"""
Anomaly Detection Analyzer
Detects security incidents from parsed log events
"""

from datetime import timedelta
from collections import defaultdict
import sys
sys.path.append('..')
import config

class AnomalyAnalyzer:
    """Analyze parsed events to detect security anomalies"""
    
    def __init__(self):
        self.anomalies = []
        
    def analyze(self, events, log_type):
        """
        Analyze events and detect anomalies
        
        Args:
            events (list): Parsed log events
            log_type (str): Type of log (ssh, web, system)
            
        Returns:
            list: Detected anomalies
        """
        self.anomalies = []
        
        if not events:
            return self.anomalies
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: x['timestamp'] if x['timestamp'] else '')
        
        # Run detection methods based on log type
        if log_type == 'ssh':
            self._detect_brute_force(sorted_events)
            self._detect_successful_breach(sorted_events)
            self._detect_off_hours_access(sorted_events)
        elif log_type == 'web':
            self._detect_scanning(sorted_events)
            self._detect_suspicious_access(sorted_events)
        elif log_type == 'system':
            self._detect_privilege_escalation(sorted_events)
            self._detect_suspicious_commands(sorted_events)
            self._detect_user_creation(sorted_events)
        
        return self.anomalies
    
    def _detect_brute_force(self, events):
        """Detect brute force attacks (multiple failed logins)"""
        failed_attempts = defaultdict(list)
        
        for event in events:
            if event['event_type'] in ['failed_login', 'invalid_user']:
                key = (event.get('ip', ''), event.get('user', ''))
                failed_attempts[key].append(event)
        
        for (ip, user), attempts in failed_attempts.items():
            if len(attempts) >= config.ANOMALY_THRESHOLDS['failed_login_threshold']:
                first_time = attempts[0]['timestamp']
                last_time = attempts[-1]['timestamp']
                duration = (last_time - first_time).total_seconds() / 60 if first_time and last_time else 0
                
                self.anomalies.append({
                    'type': 'brute_force_attack',
                    'severity': 'HIGH',
                    'ip': ip,
                    'user': user,
                    'attempts': len(attempts),
                    'duration_minutes': round(duration, 2),
                    'first_attempt': attempts[0]['raw_timestamp'],
                    'last_attempt': attempts[-1]['raw_timestamp'],
                    'description': f"Brute force attack detected: {len(attempts)} failed login attempts for user '{user}' from IP {ip} within {round(duration, 1)} minutes"
                })
    
    def _detect_successful_breach(self, events):
        """Detect successful login after multiple failures"""
        ip_timeline = defaultdict(list)
        
        for event in events:
            ip = event.get('ip', '')
            if ip:
                ip_timeline[ip].append(event)
        
        for ip, timeline in ip_timeline.items():
            failed_count = 0
            
            for event in timeline:
                if event['event_type'] in ['failed_login', 'invalid_user']:
                    failed_count += 1
                elif event['event_type'] == 'successful_login' and failed_count >= 3:
                    self.anomalies.append({
                        'type': 'successful_breach',
                        'severity': 'CRITICAL',
                        'ip': ip,
                        'user': event.get('user', ''),
                        'prior_failures': failed_count,
                        'breach_time': event['raw_timestamp'],
                        'description': f"BREACH DETECTED: Successful login for '{event.get('user', '')}' from {ip} after {failed_count} failed attempts"
                    })
                    failed_count = 0
    
    def _detect_off_hours_access(self, events):
        """Detect access during suspicious hours (2 AM - 6 AM)"""
        off_hours_start = config.ANOMALY_THRESHOLDS['off_hours_start']
        off_hours_end = config.ANOMALY_THRESHOLDS['off_hours_end']
        
        for event in events:
            if event['event_type'] == 'successful_login' and event['timestamp']:
                hour = event['timestamp'].hour
                
                if hour >= off_hours_start or hour < off_hours_end:
                    self.anomalies.append({
                        'type': 'off_hours_access',
                        'severity': 'MEDIUM',
                        'user': event.get('user', ''),
                        'ip': event.get('ip', ''),
                        'time': event['raw_timestamp'],
                        'hour': hour,
                        'description': f"Off-hours access: User '{event.get('user', '')}' logged in at {hour}:00 from {event.get('ip', '')}"
                    })
    
    def _detect_scanning(self, events):
        """Detect web scanning/reconnaissance"""
        scan_attempts = defaultdict(list)
        
        for event in events:
            if event['event_type'] in ['scanning', 'not_found']:
                scan_attempts[event['ip']].append(event)
        
        for ip, attempts in scan_attempts.items():
            if len(attempts) >= 5:
                paths = [e['path'] for e in attempts]
                
                self.anomalies.append({
                    'type': 'web_scanning',
                    'severity': 'HIGH',
                    'ip': ip,
                    'attempts': len(attempts),
                    'paths': paths[:10],
                    'description': f"Web scanning detected: {len(attempts)} failed access attempts from {ip}"
                })
    
    def _detect_suspicious_access(self, events):
        """Detect successful access to suspicious paths"""
        for event in events:
            if event['event_type'] == 'suspicious_access':
                self.anomalies.append({
                    'type': 'suspicious_access',
                    'severity': 'CRITICAL',
                    'ip': event['ip'],
                    'path': event['path'],
                    'method': event['method'],
                    'time': event['raw_timestamp'],
                    'description': f"Suspicious access: {event['method']} {event['path']} from {event['ip']} returned 200 OK"
                })
    
    def _detect_privilege_escalation(self, events):
        """Detect privilege escalation (sudo to root)"""
        for event in events:
            if event['event_type'] == 'sudo_command':
                command_lower = event['command'].lower()
                
                if any(x in command_lower for x in ['su', 'bash', 'sh', 'sudo']):
                    self.anomalies.append({
                        'type': 'privilege_escalation',
                        'severity': 'CRITICAL',
                        'user': event['user'],
                        'command': event['command'],
                        'time': event['raw_timestamp'],
                        'description': f"Privilege escalation: User '{event['user']}' executed: {event['command']}"
                    })
    
    def _detect_suspicious_commands(self, events):
        """Detect execution of suspicious commands"""
        for event in events:
            if event['event_type'] == 'sudo_command' and event.get('suspicious', False):
                if event['severity'] == 'CRITICAL':
                    self.anomalies.append({
                        'type': 'anti_forensics',
                        'severity': 'CRITICAL',
                        'user': event['user'],
                        'command': event['command'],
                        'time': event['raw_timestamp'],
                        'description': f"Anti-forensics detected: User '{event['user']}' executed: {event['command']}"
                    })
    
    def _detect_user_creation(self, events):
        """Detect new user creation (potential backdoor)"""
        for event in events:
            if event['event_type'] == 'user_added':
                self.anomalies.append({
                    'type': 'backdoor_user',
                    'severity': 'CRITICAL',
                    'new_user': event['new_user'],
                    'time': event['raw_timestamp'],
                    'description': f"New user created: '{event['new_user']}' - potential backdoor account"
                })
    
    def get_summary(self):
        """Get summary of detected anomalies"""
        summary = {
            'total_anomalies': len(self.anomalies),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int),
            'critical_count': 0,
        }
        
        for anomaly in self.anomalies:
            summary['by_severity'][anomaly['severity']] += 1
            summary['by_type'][anomaly['type']] += 1
            
            if anomaly['severity'] == 'CRITICAL':
                summary['critical_count'] += 1
        
        return dict(summary)


if __name__ == "__main__":
    print("✅ Anomaly Analyzer loaded successfully!")
    print("   Detects: Brute force, breaches, privilege escalation, scanning, suspicious commands")