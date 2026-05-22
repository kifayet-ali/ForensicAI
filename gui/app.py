"""
ForensicAI Flask Web Application
Main web interface for log analysis
"""

from flask import Flask, render_template, request, redirect, url_for, flash
import os
import sys
from werkzeug.utils import secure_filename

# Add parent directory to path
sys.path.append('..')
import config

# Import our core modules
from core.parsers.ssh_parser import SSHLogParser
from core.parsers.web_parser import WebLogParser
from core.parsers.system_parser import SystemLogParser
from core.analyzer import AnomalyAnalyzer
from core.ai_engine import AIEngine

app = Flask(__name__)
app.config['SECRET_KEY'] = config.SECRET_KEY
app.config['UPLOAD_FOLDER'] = config.UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = config.MAX_FILE_SIZE

# Create necessary directories
os.makedirs(config.UPLOAD_FOLDER, exist_ok=True)
os.makedirs(config.REPORT_FOLDER, exist_ok=True)

# Initialize AI engine
ai_engine = AIEngine()

def allowed_file(filename):
    """Check if file extension is allowed"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in config.ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page"""
    return render_template('index.html', app_name=config.APP_NAME)

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze uploaded log file"""
    
    # Check if file was uploaded
    if 'log_file' not in request.files:
        flash('No file uploaded!', 'danger')
        return redirect(url_for('index'))
    
    file = request.files['log_file']
    log_type = request.form.get('log_type', 'ssh')
    
    if file.filename == '':
        flash('No file selected!', 'danger')
        return redirect(url_for('index'))
    
    if file and allowed_file(file.filename):
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Read file content
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                log_content = f.read()
            
            # Parse logs based on type
            parser = None
            if log_type == 'ssh':
                parser = SSHLogParser()
            elif log_type == 'web':
                parser = WebLogParser()
            elif log_type == 'system':
                parser = SystemLogParser()
            else:
                flash('Invalid log type!', 'danger')
                return redirect(url_for('index'))
            
            # Parse the log file
            events = parser.parse(log_content)
            
            if not events:
                flash('No events could be parsed from this log file!', 'warning')
                return redirect(url_for('index'))
            
            # Get statistics
            stats = parser.get_statistics()
            
            # Detect anomalies
            analyzer = AnomalyAnalyzer()
            anomalies = analyzer.analyze(events, log_type)
            anomaly_summary = analyzer.get_summary()
            
            # Get AI analysis
            ai_report = ai_engine.analyze_incident(anomalies, events, log_type)
            
            # Render report
            return render_template('report.html',
                                 filename=filename,
                                 log_type=log_type,
                                 stats=stats,
                                 events=events[:50],  # Show first 50 events
                                 total_events=len(events),
                                 anomalies=anomalies,
                                 anomaly_summary=anomaly_summary,
                                 ai_report=ai_report,
                                 severity_levels=config.SEVERITY_LEVELS)
            
        except Exception as e:
            flash(f'Error analyzing log file: {str(e)}', 'danger')
            return redirect(url_for('index'))
    
    else:
        flash('Invalid file type! Please upload .log or .txt files only.', 'danger')
        return redirect(url_for('index'))

@app.route('/demo/<log_name>')
def demo(log_name):
    """Quick demo with pre-loaded logs"""
    
    demo_files = {
        'brute_force': ('../sample_logs/brute_force_attack.log', 'ssh'),
    }
    
    if log_name not in demo_files:
        flash('Demo log not found!', 'danger')
        return redirect(url_for('index'))
    
    filepath, log_type = demo_files[log_name]
    
    try:
        # Read file content
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            log_content = f.read()
        
        # Parse based on type
        if log_type == 'ssh':
            parser = SSHLogParser()
        elif log_type == 'web':
            parser = WebLogParser()
        elif log_type == 'system':
            parser = SystemLogParser()
        
        events = parser.parse(log_content)
        stats = parser.get_statistics()
        
        # Detect anomalies
        analyzer = AnomalyAnalyzer()
        anomalies = analyzer.analyze(events, log_type)
        anomaly_summary = analyzer.get_summary()
        
        # Get AI analysis
        ai_report = ai_engine.analyze_incident(anomalies, events, log_type)
        
        # Render report
        return render_template('report.html',
                             filename=filepath.split('/')[-1],
                             log_type=log_type,
                             stats=stats,
                             events=events[:50],
                             total_events=len(events),
                             anomalies=anomalies,
                             anomaly_summary=anomaly_summary,
                             ai_report=ai_report,
                             severity_levels=config.SEVERITY_LEVELS,
                             is_demo=True)
        
    except Exception as e:
        flash(f'Error loading demo: {str(e)}', 'danger')
        return redirect(url_for('index'))

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🔍 FORENSICAI - AI-POWERED INCIDENT INVESTIGATOR")
    print("="*60)
    print(f"🌐 Starting server at http://{config.HOST}:{config.PORT}")
    print(f"🤖 AI Engine: {'✅ Enabled' if ai_engine.client else '⚠️  Disabled (configure API key)'}")
    print("📁 Upload logs to analyze security incidents")
    print("="*60 + "\n")
    
    app.run(host=config.HOST, port=config.PORT, debug=config.DEBUG)