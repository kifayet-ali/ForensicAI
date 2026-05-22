"""
Unit tests for log parsers
"""
import sys
sys.path.append('..')

from core.parsers.ssh_parser import SSHLogParser
from core.parsers.web_parser import WebLogParser
from core.parsers.system_parser import SystemLogParser

def test_ssh_parser():
    """Test SSH parser with multiple scenarios"""
    parser = SSHLogParser()
    
    # Test 1: Failed login
    log1 = "Jan 15 02:15:43 server sshd[1234]: Failed password for admin from 192.168.1.100"
    events = parser.parse(log1)
    assert len(events) == 1
    assert events[0]['event_type'] == 'failed_login'
    assert events[0]['user'] == 'admin'
    assert events[0]['ip'] == '192.168.1.100'
    print("✅ Test 1 passed: Failed login detection")
    
    # Test 2: Successful login
    log2 = "Jan 15 02:16:30 server sshd[1234]: Accepted password for admin from 192.168.1.100"
    events = parser.parse(log2)
    assert len(events) == 1
    assert events[0]['event_type'] == 'successful_login'
    print("✅ Test 2 passed: Successful login detection")
    
    # Test 3: Invalid user
    log3 = "Jan 15 02:15:43 server sshd[1234]: Invalid user hacker from 192.168.1.100"
    events = parser.parse(log3)
    assert len(events) == 1
    assert events[0]['event_type'] == 'invalid_user'
    assert events[0]['severity'] == 'HIGH'
    print("✅ Test 3 passed: Invalid user detection")
    
    print("\n✅ All SSH parser tests passed!\n")

def test_web_parser():
    """Test web server parser"""
    parser = WebLogParser()
    
    # Test 1: Admin path scanning
    log1 = '192.168.1.100 - - [15/Jan/2024:02:15:43 +0000] "GET /admin.php HTTP/1.1" 404 512'
    events = parser.parse(log1)
    assert len(events) == 1
    assert events[0]['event_type'] == 'scanning'
    assert events[0]['severity'] == 'HIGH'
    print("✅ Test 1 passed: Scanning detection")
    
    # Test 2: Normal access
    log2 = '192.168.1.10 - - [15/Jan/2024:10:00:00 +0000] "GET /index.html HTTP/1.1" 200 1024'
    events = parser.parse(log2)
    assert len(events) == 1
    assert events[0]['event_type'] == 'normal_access'
    print("✅ Test 2 passed: Normal access")
    
    print("\n✅ All web parser tests passed!\n")

def test_system_parser():
    """Test system log parser"""
    parser = SystemLogParser()
    
    # Test 1: Privilege escalation
    log1 = "Jan 15 02:17:00 server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/bin/su"
    events = parser.parse(log1)
    assert len(events) == 1
    assert events[0]['event_type'] == 'sudo_command'
    assert events[0]['severity'] == 'HIGH'
    print("✅ Test 1 passed: Privilege escalation detection")
    
    # Test 2: User creation
    log2 = "Jan 15 02:19:00 server useradd[5678]: new user: name=backdoor"
    events = parser.parse(log2)
    assert len(events) == 1
    assert events[0]['event_type'] == 'user_added'
    assert events[0]['severity'] == 'HIGH'
    print("✅ Test 2 passed: User creation detection")
    
    print("\n✅ All system parser tests passed!\n")

if __name__ == "__main__":
    print("="*60)
    print("RUNNING FORENSICAI PARSER TESTS")
    print("="*60 + "\n")
    
    test_ssh_parser()
    test_web_parser()
    test_system_parser()
    
    print("="*60)
    print("🎉 ALL TESTS PASSED!")
    print("="*60)