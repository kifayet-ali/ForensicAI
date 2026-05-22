"""
ForensicAI Configuration File
"""

# Anthropic Claude API Configuration
# Get your free API key from: https://console.anthropic.com/
ANTHROPIC_API_KEY = "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"  # Replace with your actual API key
CLAUDE_MODEL = "claude-sonnet-4-20250514"

# Flask Configuration
SECRET_KEY = "forensic-ai-secret-key-2024"
DEBUG = True
HOST = "0.0.0.0"
PORT = 5000

# Upload Configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'log', 'txt'}
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

# Analysis Configuration
ANOMALY_THRESHOLDS = {
    'failed_login_threshold': 3,
    'time_window_minutes': 5,
    'off_hours_start': 22,
    'off_hours_end': 6,
    'bulk_operation_threshold': 10,
}

# Suspicious Commands
SUSPICIOUS_COMMANDS = [
    'rm -rf', 'wget', 'curl', 'nc', 'netcat',
    '/bin/bash', '/bin/sh', 'chmod 777', 'chmod +x',
    'dd if=', 'mkfs', 'fdisk',
]

# Suspicious Paths
SUSPICIOUS_PATHS = [
    '/etc/passwd', '/etc/shadow', '/var/log/',
    '.ssh/', 'authorized_keys', '/tmp/', '/dev/tcp',
]

# Report Configuration
REPORT_FOLDER = "reports"
SEVERITY_LEVELS = {
    'CRITICAL': {'color': '#dc3545', 'icon': '🚨'},
    'HIGH': {'color': '#fd7e14', 'icon': '⚠️'},
    'MEDIUM': {'color': '#ffc107', 'icon': '⚡'},
    'LOW': {'color': '#28a745', 'icon': 'ℹ️'},
    'INFO': {'color': '#17a2b8', 'icon': '📋'},
}

# Application Metadata
APP_NAME = "ForensicAI"
APP_VERSION = "1.0.0"
APP_DESCRIPTION = "AI-Powered Incident Investigator"