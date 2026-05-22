"""
SSH/Authentication Log Parser
Parses SSH and authentication logs to extract security events
"""

import re
from datetime import datetime
from dateutil import parser as date_parser

class SSHLogParser:
    """Parse SSH and authentication logs"""
    
    def __init__(self):
        self.events = []
        
    def parse(self, log_content):
        """
        Parse SSH log content and extract security events
        
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
        """Parse a single log line"""
        
        # Failed password attempts
        failed_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[(\d+)\]:\s+Failed password for (\S+) from (\S+)'
        match = re.search(failed_pattern, line)
        if match:
            return {
                'timestamp': self._parse_timestamp(match.group(1)),
                'raw_timestamp': match.group(1),
                'hostname': match.group(2),
                'pid': match.group(3),
                'event_type': 'failed_login',
                'user': match.group(4),
                'ip': match.group(5),
                'severity': 'MEDIUM',
                'message': f"Failed login attempt for user '{match.group(4)}' from {match.group(5)}"
            }
        
        # Successful authentication
        success_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[(\d+)\]:\s+Accepted password for (\S+) from (\S+)'
        match = re.search(success_pattern, line)
        if match:
            return {
                'timestamp': self._parse_timestamp(match.group(1)),
                'raw_timestamp': match.group(1),
                'hostname': match.group(2),
                'pid': match.group(3),
                'event_type': 'successful_login',
                'user': match.group(4),
                'ip': match.group(5),
                'severity': 'INFO',
                'message': f"Successful login for user '{match.group(4)}' from {match.group(5)}"
            }
        
        # Invalid user attempts
        invalid_pattern = r'(\w+\s+\d+\s+\d+:\d+:\d+)\s+(\S+)\s+sshd\[(\d+)\]:\s+Invalid user (\S+) from (\S+)'
        match = re.search(invalid_pattern, line)
        if match:
            return {
                'timestamp': self._parse_timestamp(match.group(1)),
                'raw_timestamp': match.group(1),
                'hostname': match.group(2),
                'pid': match.group(3),
                'event_type': 'invalid_user',
                'user': match.group(4),
                'ip': match.group(5),
                'severity': 'HIGH',
                'message': f"Login attempt with invalid user '{match.group(4)}' from {match.group(5)}"
            }
        
        return None
    
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
            'failed_logins': 0,
            'successful_logins': 0,
            'invalid_users': 0,
            'unique_ips': set(),
            'unique_users': set(),
        }
        
        for event in self.events:
            if event['event_type'] == 'failed_login':
                stats['failed_logins'] += 1
            elif event['event_type'] == 'successful_login':
                stats['successful_logins'] += 1
            elif event['event_type'] == 'invalid_user':
                stats['invalid_users'] += 1
            
            if 'ip' in event:
                stats['unique_ips'].add(event['ip'])
            if 'user' in event:
                stats['unique_users'].add(event['user'])
        
        stats['unique_ips'] = list(stats['unique_ips'])
        stats['unique_users'] = list(stats['unique_users'])
        
        return stats


if __name__ == "__main__":
    # Test the parser
    sample_log = """Jan 15 02:15:43 server sshd[1234]: Failed password for admin from 192.168.1.100
Jan 15 02:15:45 server sshd[1234]: Failed password for admin from 192.168.1.100
Jan 15 02:15:47 server sshd[1234]: Failed password for admin from 192.168.1.100
Jan 15 02:16:30 server sshd[1234]: Accepted password for admin from 192.168.1.100"""
    
    parser = SSHLogParser()
    events = parser.parse(sample_log)
    
    print(f"\n✅ Parsed {len(events)} events:")
    for event in events:
        print(f"  - {event['event_type']}: {event['message']}")
    
    stats = parser.get_statistics()
    print(f"\n📊 Statistics:")
    print(f"  Failed logins: {stats['failed_logins']}")
    print(f"  Successful logins: {stats['successful_logins']}")
    print(f"  Unique IPs: {len(stats['unique_ips'])}")