"""
AI Engine - Claude API Integration
Sends anomalies to Claude AI for natural language analysis
"""

import anthropic
import json
import sys
sys.path.append('..')
import config

class AIEngine:
    """Interface with Claude AI for incident analysis"""
    
    def __init__(self):
        self.client = None
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Anthropic Claude client"""
        api_key = config.ANTHROPIC_API_KEY
        
        if api_key == "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":
            print("⚠️  WARNING: Claude API key not configured!")
            print("   Please set ANTHROPIC_API_KEY in config.py")
            print("   Get free API key from: https://console.anthropic.com/")
            return
        
        try:
            self.client = anthropic.Anthropic(api_key=api_key)
            print("✅ Claude AI initialized successfully")
        except Exception as e:
            print(f"❌ Failed to initialize Claude AI: {e}")
    
    def analyze_incident(self, anomalies, events, log_type):
        """
        Send anomalies to Claude AI for narrative analysis
        
        Args:
            anomalies (list): Detected anomalies
            events (list): All parsed events
            log_type (str): Type of log
            
        Returns:
            str: AI-generated incident report
        """
        if not self.client:
            return self._generate_fallback_report(anomalies, log_type)
        
        try:
            # Prepare context for Claude
            context = self._prepare_context(anomalies, events, log_type)
            
            # Create the prompt
            prompt = self._create_prompt(context)
            
            # Call Claude API
            message = self.client.messages.create(
                model=config.CLAUDE_MODEL,
                max_tokens=2000,
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            # Extract text response
            report = message.content[0].text
            
            return report
            
        except Exception as e:
            print(f"❌ Claude AI error: {e}")
            return self._generate_fallback_report(anomalies, log_type)
    
    def _prepare_context(self, anomalies, events, log_type):
        """Prepare context data for Claude"""
        context = {
            'log_type': log_type,
            'total_events': len(events),
            'total_anomalies': len(anomalies),
            'anomalies': anomalies,
            'timeline': []
        }
        
        # Create timeline
        for anomaly in anomalies:
            timeline_entry = {
                'type': anomaly['type'],
                'severity': anomaly['severity'],
                'description': anomaly['description']
            }
            
            if 'time' in anomaly:
                timeline_entry['time'] = anomaly['time']
            elif 'breach_time' in anomaly:
                timeline_entry['time'] = anomaly['breach_time']
            elif 'first_attempt' in anomaly:
                timeline_entry['time'] = anomaly['first_attempt']
            
            context['timeline'].append(timeline_entry)
        
        return context
    
    def _create_prompt(self, context):
        """Create prompt for Claude AI"""
        
        prompt = f"""You are a cybersecurity forensic analyst. Analyze this security incident and provide a clear, professional report.

LOG TYPE: {context['log_type'].upper()}
TOTAL EVENTS ANALYZED: {context['total_events']}
ANOMALIES DETECTED: {context['total_anomalies']}

DETECTED ANOMALIES:
{json.dumps(context['anomalies'], indent=2)}

INSTRUCTIONS:
1. Create a timeline narrative explaining what happened step-by-step
2. Identify the attack type and techniques used
3. Assess the severity and potential impact
4. Provide specific IOCs (IP addresses, usernames, etc.)
5. Give actionable security recommendations

FORMAT YOUR RESPONSE AS:

🚨 INCIDENT ANALYSIS REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

📋 EXECUTIVE SUMMARY
[Brief overview of what happened]

⏱️ TIMELINE RECONSTRUCTION
[Step-by-step narrative of the attack, with timestamps]

🎯 ATTACK CLASSIFICATION
Attack Type: [e.g., Brute Force Attack]
Techniques: [MITRE ATT&CK techniques if applicable]
Sophistication: [Low/Medium/High]

⚠️ SEVERITY ASSESSMENT
Overall Severity: [CRITICAL/HIGH/MEDIUM/LOW]
Potential Impact: [What damage could this cause]
Evidence Quality: [How reliable is this detection]

🔍 INDICATORS OF COMPROMISE (IOCs)
[List all IPs, usernames, commands, etc.]

💡 RECOMMENDATIONS
[Numbered list of specific actions to take]

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Use professional but clear language. Be specific with times, IPs, and commands."""
        
        return prompt
    
    def _generate_fallback_report(self, anomalies, log_type):
        """Generate a basic report when AI is unavailable"""
        
        report = f"""🚨 INCIDENT ANALYSIS REPORT
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

⚠️  Note: AI analysis unavailable - showing basic detection results

📋 DETECTION SUMMARY
Log Type: {log_type.upper()}
Anomalies Detected: {len(anomalies)}

🔍 DETECTED INCIDENTS:
"""
        
        for i, anomaly in enumerate(anomalies, 1):
            severity_icon = config.SEVERITY_LEVELS.get(anomaly['severity'], {}).get('icon', '⚠️')
            report += f"\n{i}. [{severity_icon} {anomaly['severity']}] {anomaly['type'].upper()}\n"
            report += f"   {anomaly['description']}\n"
        
        report += """
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 RECOMMENDATIONS:
1. Review the detected anomalies above
2. Investigate source IPs and user accounts
3. Check system logs for additional context
4. Implement security controls to prevent recurrence

Note: Configure Claude API key in config.py for AI-powered analysis.
Get free API key from: https://console.anthropic.com/
"""
        
        return report


if __name__ == "__main__":
    # Test AI engine
    engine = AIEngine()
    
    # Test with sample anomaly
    test_anomalies = [{
        'type': 'brute_force_attack',
        'severity': 'HIGH',
        'ip': '192.168.1.100',
        'user': 'admin',
        'attempts': 47,
        'description': 'Brute force attack detected: 47 failed login attempts'
    }]
    
    if engine.client:
        print("\n🤖 Testing Claude AI...")
        report = engine.analyze_incident(test_anomalies, [], 'ssh')
        print(report)
    else:
        print("\n⚠️  Claude API not configured")
        print("   Fallback mode will be used")