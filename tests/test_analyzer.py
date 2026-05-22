import sys
sys.path.append('..')

from core.parsers.ssh_parser import SSHLogParser
from core.analyzer import AnomalyAnalyzer

def test_slow_brute_force():
    """Test slow brute force detection"""
    
    # Generate 25 failed attempts over 48 minutes (every 2 minutes)
    # This should trigger slow brute force (>20 attempts, >30 min duration)
    log_lines = []
    for i in range(25):
        minute = 10 + (i * 2)  # Start at 10, increment by 2 each time
        # minute will go: 10, 12, 14, 16, ... 58
        # After minute 58, it wraps to next hour
        if minute >= 60:
            hour = 3
            minute = minute - 60
            log_lines.append(f"Jan 15 0{hour}:{minute:02d}:00 server sshd[1234]: Failed password for admin from 192.168.1.100 port 5000 ssh2")
        else:
            log_lines.append(f"Jan 15 02:{minute:02d}:00 server sshd[1234]: Failed password for admin from 192.168.1.100 port 5000 ssh2")
    
    log_content = '\n'.join(log_lines)
    
    # Debug: Print first and last log line
    print(f"\nFirst log line: {log_lines[0]}")
    print(f"Last log line:  {log_lines[-1]}")
    print(f"Total log lines: {len(log_lines)}\n")
    
    # Parse logs
    parser = SSHLogParser()
    events = parser.parse(log_content)
    
    print(f"Parsed {len(events)} events")
    if events:
        print(f"First event timestamp: {events[0]['raw_timestamp']}")
        print(f"Last event timestamp:  {events[-1]['raw_timestamp']}")
    
    # Analyze for anomalies
    analyzer = AnomalyAnalyzer()
    anomalies = analyzer.analyze(events, 'ssh')
    
    print(f"\nTotal anomalies detected: {len(anomalies)}")
    for anomaly in anomalies:
        print(f"  - {anomaly['type']}: {anomaly['description']}")
    
    # Check for slow brute force
    slow_bf = [a for a in anomalies if a['type'] == 'slow_brute_force']
    
    if len(slow_bf) > 0:
        print(f"\n✅ Detected slow brute force: {slow_bf[0]['description']}")
    else:
        print("\n❌ Slow brute force NOT detected")
        print(f"   Note: Detection requires >20 attempts over >30 minutes")
        
        # Check what WAS detected
        brute_force = [a for a in anomalies if a['type'] == 'brute_force_attack']
        if brute_force:
            print(f"   Regular brute force detected instead:")
            print(f"   {brute_force[0]['description']}")
    
    assert len(slow_bf) > 0, "Should detect slow brute force"

if __name__ == "__main__":
    print("="*60)
    print("TESTING SLOW BRUTE FORCE DETECTION")
    print("="*60)
    
    test_slow_brute_force()
    
    print("\n" + "="*60)
    print("🎉 ALL TESTS PASSED!")
    print("="*60)