"""
Web Server Log Parser
Parses Apache and Nginx access logs
"""

import re
from datetime import datetime
from dateutil import parser as date_parser

class WebLogParser:
    """Parse web server (Apache/Nginx) access logs"""
    
    def __init__(self):
        self.events = []
        
    def parse(self, log_content):
        """
        Parse web server log content and extract events
        
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
        """Parse a single Apache/Nginx log line"""
        
        # Apache/Nginx Combined Log Format
        pattern = r'(\S+) - - \[(.*?)\] "(\S+) (\S+) (\S+)" (\d+) (\d+)'
        
        match = re.search(pattern, line)
        if match:
            ip = match.group(1)
            timestamp_str = match.group(2)
            method = match.group(3)
            path = match.group(4)
            protocol = match.group(5)
            status = int(match.group(6))
            size = int(match.group(7))
            
            # Determine event type and severity
            event_type, severity = self._classify_request(method, path, status)
            
            return {
                'timestamp': self._parse_timestamp(timestamp_str),
                'raw_timestamp': timestamp_str,
                'ip': ip,
                'method': method,
                'path': path,
                'protocol': protocol,
                'status': status,
                'size': size,
                'event_type': event_type,
                'severity': severity,
                'message': f"{method} {path} - Status {status}"
            }
        
        return None
    
    def _classify_request(self, method, path, status):
        """Classify request based on method, path, and status"""
        
        suspicious_paths = [
            'admin', 'wp-admin', 'phpmyadmin', '.env', 'config',
            '../', '..\\', '/etc/passwd', 'shell', 'cmd', 'exec',
            'sqlmap', 'sql', 'union', 'select', '<script'
        ]
        
        path_lower = path.lower()
        is_suspicious = any(sus in path_lower for sus in suspicious_paths)
        
        if status == 404 and is_suspicious:
            return 'scanning', 'HIGH'
        elif status == 404:
            return 'not_found', 'LOW'
        elif status == 403:
            return 'forbidden', 'MEDIUM'
        elif status == 401:
            return 'unauthorized', 'MEDIUM'
        elif status >= 500:
            return 'server_error', 'MEDIUM'
        elif is_suspicious and status == 200:
            return 'suspicious_access', 'CRITICAL'
        elif method in ['POST', 'PUT', 'DELETE']:
            return 'data_modification', 'MEDIUM'
        elif status == 200:
            return 'normal_access', 'INFO'
        else:
            return 'other', 'LOW'
    
    def _parse_timestamp(self, timestamp_str):
        """Convert web server timestamp to datetime object"""
        try:
            return datetime.strptime(timestamp_str, '%d/%b/%Y:%H:%M:%S %z')
        except:
            try:
                return date_parser.parse(timestamp_str)
            except:
                return None
    
    def get_statistics(self):
        """Get statistics from parsed events"""
        stats = {
            'total_requests': len(self.events),
            'status_codes': {},
            'methods': {},
            'unique_ips': set(),
            'suspicious_requests': 0,
            'top_paths': {},
        }
        
        for event in self.events:
            status = event['status']
            stats['status_codes'][status] = stats['status_codes'].get(status, 0) + 1
            
            method = event['method']
            stats['methods'][method] = stats['methods'].get(method, 0) + 1
            
            stats['unique_ips'].add(event['ip'])
            
            if event['event_type'] in ['scanning', 'suspicious_access']:
                stats['suspicious_requests'] += 1
            
            path = event['path']
            stats['top_paths'][path] = stats['top_paths'].get(path, 0) + 1
        
        stats['unique_ips'] = list(stats['unique_ips'])
        stats['top_paths'] = dict(sorted(stats['top_paths'].items(), 
                                        key=lambda x: x[1], 
                                        reverse=True)[:10])
        
        return stats


if __name__ == "__main__":
    # Test the parser
    sample_log = """192.168.1.100 - - [15/Jan/2024:02:15:43 +0000] "GET /admin.php HTTP/1.1" 404 512
192.168.1.100 - - [15/Jan/2024:02:15:45 +0000] "GET /wp-admin/ HTTP/1.1" 404 512
192.168.1.100 - - [15/Jan/2024:02:15:47 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 512
192.168.1.100 - - [15/Jan/2024:02:16:30 +0000] "GET /index.html HTTP/1.1" 200 1024"""
    
    parser = WebLogParser()
    events = parser.parse(sample_log)
    
    print(f"\n✅ Parsed {len(events)} events:")
    for event in events:
        print(f"  - [{event['severity']}] {event['event_type']}: {event['message']}")
    
    stats = parser.get_statistics()
    print(f"\n📊 Statistics:")
    print(f"  Total requests: {stats['total_requests']}")
    print(f"  Suspicious requests: {stats['suspicious_requests']}")
    print(f"  Unique IPs: {len(stats['unique_ips'])}")