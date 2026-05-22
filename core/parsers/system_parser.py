"""
System Log Parser
Parses system logs for sudo commands, file operations, and privilege escalation
"""

import re
from datetime import datetime
from dateutil import parser as date_parser
import sys
sys.path.append('../..')
import config

class SystemLogParser:
    """Parse system logs for security events"""
    
    def __init__(self):
        self.events = []
        
    def parse(self, log_content):
        """
        Parse system log content and extract security events
        
        Args:
            log_content (str): Raw log file content
            
        Returns:
            list: Parsed events
        """
        self.events = []
        lines = log_content.strip().split('\n')
        
        for line in lines:
            event = self._parse_line(line)
            if event:
                self.events.append(event)
        
        return self.events
    
    def _parse_line(self, line):
        """Parse a single system log line"""
        
        # Sudo command execution
        sudo_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sudo:\s+(\S+)\s+:.*?COMMAND=(.+)'
        match = re.search(sudo_pattern, line)
        if match:
            timestamp_str = match.group(1)
            hostname = match.group(2)
            user = match.group(3)
            command = match.group(4)
            
            severity, is_suspicious = self._check_command_suspicion(command)
            
            return {
                'timestamp': self._parse_timestamp(timestamp_str),
                'raw_timestamp': timestamp_str,
                'hostname': hostname,
                'user': user,
                'command': command,
                'event_type': 'sudo_command',
                'severity': severity,
                'suspicious': is_suspicious,
                'message': f"User '{user}' executed sudo command: {command}"
            }
        
        # Audit log events
        audit_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+audit:.*?type=(\w+).*?msg=\'(.+?)\''
        match = re.search(audit_pattern, line)
        if match:
            timestamp_str = match.group(1)
            hostname = match.group(2)
            audit_type = match.group(3)
            message = match.group(4)
            
            severity = 'HIGH' if audit_type in ['USER_CMD', 'SYSCALL'] else 'MEDIUM'
            
            return {
                'timestamp': self._parse_timestamp(timestamp_str),
                'raw_timestamp': timestamp_str,
                'hostname': hostname,
                'audit_type': audit_type,
                'event_type': 'audit_event',
                'severity': severity,
                'message': f"Audit event ({audit_type}): {message}"
            }
        
        # User add/delete
        useradd_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+useradd\[(\d+)\]:\s+new user:\s+name=(\S+)'
        match = re.search(useradd_pattern, line)
        if match:
            return {
                'timestamp': self._parse_timestamp(match.group(1)),
                'raw_timestamp': match.group(1),
                'hostname': match.group(2),
                'pid': match.group(3),
                'new_user': match.group(4),
                'event_type': 'user_added',
                'severity': 'HIGH',
                'message': f"New user created: {match.group(4)}"
            }
        
        return None
    
    def _check_command_suspicion(self, command):
        """Check if a command is suspicious"""
        command_lower = command.lower()
        
        # Critical commands
        critical_commands = ['rm -rf', 'dd if=', 'mkfs', 'fdisk']
        for cmd in critical_commands:
            if cmd in command_lower:
                return 'CRITICAL', True
        
        # Check against config suspicious commands
        for sus_cmd in config.SUSPICIOUS_COMMANDS:
            if sus_cmd in command_lower:
                return 'HIGH', True
        
        # Check against suspicious paths
        for sus_path in config.SUSPICIOUS_PATHS:
            if sus_path in command_lower:
                return 'HIGH', True
        
        # Privilege escalation
        if any(x in command_lower for x in ['su', 'sudo', 'bash', 'sh']):
            return 'HIGH', True
        
        return 'MEDIUM', False
    
    def _parse_timestamp(self, timestamp_str):
        """Convert log timestamp to datetime object"""
        try:
            current_year = datetime.now().year
            timestamp_with_year = f"{timestamp_str} {current_year}"
            return date_parser.parse(timestamp_with_year)
        except:
            return None
    
    def get_statistics(self):
        """Get statistics from parsed events"""
        stats = {
            'total_events': len(self.events),
            'sudo_commands': 0,
            'suspicious_commands': 0,
            'user_changes': 0,
            'unique_users': set(),
        }
        
        for event in self.events:
            if event['event_type'] == 'sudo_command':
                stats['sudo_commands'] += 1
                if event.get('suspicious', False):
                    stats['suspicious_commands'] += 1
            elif event['event_type'] == 'user_added':
                stats['user_changes'] += 1
            
            if 'user' in event:
                stats['unique_users'].add(event['user'])
        
        stats['unique_users'] = list(stats['unique_users'])
        
        return stats


if __name__ == "__main__":
    # Test the parser
    sample_log = """Jan 15 02:17:00 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/su
Jan 15 02:18:15 server audit: type=USER_CMD msg='rm -rf /var/log/secure'
Jan 15 02:19:00 server useradd[5678]: new user: name=backdoor"""
    
    parser = SystemLogParser()
    events = parser.parse(sample_log)
    
    print(f"\n✅ Parsed {len(events)} events:")
    for event in events:
        print(f"  - [{event['severity']}] {event['event_type']}: {event['message']}")
    
    stats = parser.get_statistics()
    print(f"\n📊 Statistics:")
    print(f"  Sudo commands: {stats['sudo_commands']}")
    print(f"  Suspicious commands: {stats['suspicious_commands']}")