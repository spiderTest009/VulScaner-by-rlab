from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit, join_room
import threading
import uuid
import os
import datetime
import logging
from webscaner import RLabsWebScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'vulscanner-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Create reports directory
REPORTS_DIR = 'reports'
if not os.path.exists(REPORTS_DIR):
    os.makedirs(REPORTS_DIR)

active_scans = {}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json()
    target_url = data.get('url')
    
    if not target_url:
        return jsonify({'error': 'URL is required'}), 400
    
    scan_id = str(uuid.uuid4())
    active_scans[scan_id] = {
        'url': target_url,
        'status': 'running',
        'start_time': datetime.datetime.now()
    }
    
    thread = threading.Thread(target=run_scan, args=(scan_id, target_url))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'scan_id': scan_id})

def run_scan(scan_id, target_url):
    try:
        def emit_progress(message, level='INFO'):
            timestamp = datetime.datetime.now().strftime("%H:%M:%S")
            logger.info(f"[{scan_id[:8]}] {message}")
            socketio.emit('scan_progress', {
                'scan_id': scan_id,
                'message': message,
                'timestamp': timestamp,
                'level': level
            }, room=scan_id)
            socketio.sleep(0.1)  # Small delay to ensure message is sent
        
        # Immediate first message
        emit_progress("🚀 Security scan initiated...")
        emit_progress(f"Target: {target_url}")
        
        logger.info(f"Starting scan for {target_url}")
        emit_progress("Initializing scanner components...")
        scanner = RLabsWebScanner(target_url)
        
        emit_progress("Resolving hostname...")
        scanner.resolve_hostname()
        emit_progress(f"✓ Resolved to IP: {scanner.results['ip_address']}")
        
        emit_progress("Scanning common ports...")
        scanner.port_scan()
        if scanner.results['open_ports']:
            for port in scanner.results['open_ports']:
                emit_progress(f"🔍 Found open port: {port['port']}/{port['protocol']} ({port['service']})")
        else:
            emit_progress("✓ No open ports found in scan range")
        
        emit_progress("Analyzing HTTP headers...")
        scanner.analyze_http_headers()
        emit_progress(f"✓ Analyzed {len(scanner.results['security_headers'])} security headers")
        
        emit_progress("Checking SSL certificate...")
        scanner.check_ssl_certificate()
        if scanner.results['ssl_info']:
            emit_progress("✓ SSL certificate found and analyzed")
        else:
            emit_progress("⚠️ No SSL certificate found")
        
        emit_progress("Detecting web technologies...")
        scanner.detect_technologies()
        if scanner.results['technologies']:
            emit_progress(f"✓ Detected {len(scanner.results['technologies'])} technologies")
        
        emit_progress("Generating security recommendations...")
        scanner.generate_recommendations()
        emit_progress(f"✓ Generated {len(scanner.results['recommendations'])} recommendations")
        
        emit_progress("Getting AI-powered security analysis...")
        scanner.get_ai_recommendations()
        emit_progress(f"🤖 Security score: {scanner.results['security_score']}/100")
        emit_progress(f"📊 Risk level: {scanner.results['risk_level']}")
        
        emit_progress("Generating comprehensive PDF report...")
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{scanner.hostname}_{timestamp}.pdf"
        report_path = os.path.join(REPORTS_DIR, filename)
        
        scanner.generate_pdf_report(report_path)
        emit_progress(f"📄 PDF report saved: {filename}")
        
        active_scans[scan_id]['status'] = 'completed'
        active_scans[scan_id]['report_path'] = report_path
        active_scans[scan_id]['results'] = scanner.results
        
        logger.info(f"Scan completed successfully")
        emit_progress("🎉 Scan completed! Report ready for download.", 'SUCCESS')
        
        socketio.emit('scan_complete', {
            'scan_id': scan_id,
            'download_url': f'/api/download/{scan_id}',
            'summary': {
                'target': scanner.results['target'],
                'security_score': scanner.results['security_score'],
                'risk_level': scanner.results['risk_level'],
                'open_ports': len(scanner.results['open_ports']),
                'recommendations': len(scanner.results['recommendations'])
            }
        }, room=scan_id)
        
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        active_scans[scan_id]['status'] = 'failed'
        socketio.emit('scan_error', {'scan_id': scan_id, 'error': str(e)}, room=scan_id)

@app.route('/api/download/<scan_id>')
def download_report(scan_id):
    if scan_id not in active_scans:
        return jsonify({'error': 'Scan not found'}), 404
    
    scan_info = active_scans[scan_id]
    
    if scan_info['status'] != 'completed':
        return jsonify({'error': 'Scan not completed yet'}), 400
    
    report_path = scan_info.get('report_path')
    if not report_path or not os.path.exists(report_path):
        return jsonify({'error': 'Report file not found'}), 404
    
    return send_file(report_path, as_attachment=True, download_name=os.path.basename(report_path))

@socketio.on('join_scan')
def on_join_scan(data):
    join_room(data['scan_id'])

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)