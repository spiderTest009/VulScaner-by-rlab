#!/usr/bin/env python3
"""
RLabs Security Web Scanner - Professional Security Assessment Tool
Company: RLabs Security (https://rlabs-security.com/)
Performs non-intrusive scans and generates professional PDF reports with AI-powered recommendations
"""

import socket
import requests
import subprocess
import json
import datetime
import sys
import re
import ssl
from urllib.parse import urlparse
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT, TA_JUSTIFY
from reportlab.platypus.tableofcontents import TableOfContents
from reportlab.lib.utils import ImageReader
import argparse
import google.generativeai as genai
import os
from dotenv import load_dotenv
from io import BytesIO

# Load environment variables
load_dotenv()
import base64
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.backends.backend_pdf import PdfPages
import numpy as np

class RLabsWebScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.parsed_url = urlparse(target_url)
        self.hostname = self.parsed_url.hostname
        self.company_name = "Rlabs"
        self.company_website = "https://rlabs-security.com/"
        self.scan_type = "Free Basic Security Scan"
        
        self.results = {
            'target': target_url,
            'hostname': self.hostname,
            'scan_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'ip_address': '',
            'open_ports': [],
            'technologies': {},
            'headers': {},
            'ssl_info': {},
            'security_headers': {},
            'recommendations': [],
            'risk_level': 'Unknown',
            'security_score': 0,
            'ai_recommendations': ''
        }

    def setup_gemini_api(self):
        """Setup Gemini AI API with provided key"""
        try:
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                raise ValueError("GEMINI_API_KEY not found in environment variables")
            genai.configure(api_key=api_key)
            return True
        except Exception as e:
            print(f"[-] Gemini API setup failed: {str(e)}")
            return False

    def get_ai_recommendations(self):
        """Get AI-powered recommendations from Gemini"""
        try:
            api_key = os.getenv('GEMINI_API_KEY')
            if not api_key:
                raise ValueError("GEMINI_API_KEY not found in environment variables")
            genai.configure(api_key=api_key)
            model = genai.GenerativeModel('gemini-1.5-flash')
            
            # Prepare scan data for AI analysis
            scan_summary = f"""
            Web Security Scan Results for {self.target_url}:
            
            Target Information:
            - URL: {self.target_url}
            - IP Address: {self.results['ip_address']}
            - Scan Date: {self.results['scan_time']}
            
            Open Ports: {len(self.results['open_ports'])} ports found
            {[f"Port {p['port']}/{p['protocol']} ({p['service']})" for p in self.results['open_ports']]}
            
            Security Headers Analysis:
            {[f"{h}: {'Present' if info['present'] else 'Missing'}" for h, info in self.results['security_headers'].items()]}
            
            Technologies Detected:
            {list(self.results['technologies'].keys())}
            
            SSL Certificate: {'Available' if self.results['ssl_info'] else 'Not checked/available'}
            
            Current Basic Recommendations:
            {self.results['recommendations']}
            """
            
            prompt = f"""
            As a cybersecurity expert from Rlabs, analyze this web security scan report and provide professional recommendations:

            {scan_summary}

            IMPORTANT: You MUST provide a specific security score between 1-100 based on the findings.
            
            Scoring criteria:
            - Start with base score of 70
            - Deduct 10 points for each missing critical security header (HSTS, CSP, X-Frame-Options)
            - Deduct 15 points for each high-risk open port (21, 23, 25, 110)
            - Deduct 5 points for each medium-risk port (22, 80)
            - Add 10 points if HTTPS is used
            - Add 5 points for each security header present
            - Deduct 20 points if using HTTP only

            Please provide:
            1. SECURITY SCORE: [NUMBER]/100 (must be clearly stated)
            2. Risk level (Low/Medium/High/Critical)
            3. Priority recommendations for improving security
            4. Specific technical suggestions based on the findings

            Format your response professionally for inclusion in a security report.
            """

            response = model.generate_content(prompt)
            self.results['ai_recommendations'] = response.text
            
            # Extract risk level and security score from AI response
            self._parse_ai_response(response.text)
            
            print("[+] AI recommendations generated successfully")
            
        except Exception as e:
            print(f"[-] AI recommendation generation failed: {str(e)}")
            self.results['ai_recommendations'] = f"AI recommendations failed: {str(e)}"
            # Ensure we have a score even if AI fails
            if self.results['security_score'] == 0:
                self.results['security_score'] = self._calculate_fallback_score()

    def _calculate_fallback_score(self):
        """Calculate security score based on scan findings"""
        score = 70  # Base score
        
        # Check security headers
        critical_headers = ['Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options']
        for header in critical_headers:
            if header in self.results['security_headers'] and not self.results['security_headers'][header]['present']:
                score -= 10
        
        # Check for HTTPS
        if self.parsed_url.scheme == 'https':
            score += 10
        else:
            score -= 20
        
        # Check open ports
        high_risk_ports = [21, 23, 25, 110]
        medium_risk_ports = [22, 80]
        
        for port_info in self.results['open_ports']:
            if port_info['port'] in high_risk_ports:
                score -= 15
            elif port_info['port'] in medium_risk_ports:
                score -= 5
        
        # Add points for present security headers
        present_headers = sum(1 for h in self.results['security_headers'].values() if h['present'])
        score += min(present_headers * 3, 15)  # Max 15 bonus points
        
        return max(10, min(100, score))  # Ensure score is between 10-100

    def _parse_ai_response(self, ai_response):
        """Parse AI response to extract risk level and security score"""
        try:
            # Extract risk level
            risk_patterns = [
                r'risk level.*?(low|medium|high|critical)',
                r'security.*?level.*?(low|medium|high|critical)',
                r'risk.*?(low|medium|high|critical)'
            ]
            
            for pattern in risk_patterns:
                match = re.search(pattern, ai_response.lower())
                if match:
                    self.results['risk_level'] = match.group(1).title()
                    break
            
            # Extract security score with multiple patterns
            score_patterns = [
                r'SECURITY SCORE:\s*(\d+)',
                r'security score.*?(\d+)',
                r'score.*?(\d+)(?:/100|\s*out\s*of\s*100)',
                r'(\d+)(?:/100|\s*out\s*of\s*100)'
            ]
            
            for pattern in score_patterns:
                match = re.search(pattern, ai_response, re.IGNORECASE)
                if match:
                    score = int(match.group(1))
                    if 0 <= score <= 100:
                        self.results['security_score'] = score
                        break
            
            # Fallback scoring if AI doesn't provide score
            if self.results['security_score'] == 0:
                self.results['security_score'] = self._calculate_fallback_score()
                        
        except Exception as e:
            print(f"[-] Error parsing AI response: {str(e)}")
            # Ensure we always have a score
            if self.results['security_score'] == 0:
                self.results['security_score'] = self._calculate_fallback_score()

    def resolve_hostname(self):
        """Resolve hostname to IP address"""
        try:
            self.results['ip_address'] = socket.gethostbyname(self.hostname)
            print(f"[+] Resolved {self.hostname} to {self.results['ip_address']}")
        except socket.gaierror:
            print(f"[-] Could not resolve {self.hostname}")
            self.results['ip_address'] = 'Unable to resolve'

    def port_scan(self, ports=[80, 443, 21, 22, 25, 53, 110, 993, 995]):
        """Basic port scan using socket"""
        print(f"[+] Scanning common ports on {self.hostname}...")
        self._basic_port_scan(ports)

    def _basic_port_scan(self, ports):
        """Fallback basic port scan using socket"""
        print("[+] Using basic socket scan...")
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.hostname, port))
                
                if result == 0:
                    service = self._get_service_name(port)
                    self.results['open_ports'].append({
                        'port': port,
                        'protocol': 'tcp',
                        'service': service,
                        'state': 'open'
                    })
                    print(f"[+] Port {port}/tcp ({service}) - open")
                
                sock.close()
            except Exception as e:
                continue

    def _get_service_name(self, port):
        """Get service name for common ports"""
        services = {
            21: 'ftp', 22: 'ssh', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 443: 'https',
            993: 'imaps', 995: 'pop3s'
        }
        return services.get(port, 'unknown')

    def analyze_http_headers(self):
        """Analyze HTTP headers for security information"""
        try:
            print(f"[+] Analyzing HTTP headers...")
            response = requests.get(self.target_url, timeout=10, verify=False)
            self.results['headers'] = dict(response.headers)
            
            # Check for security headers
            security_headers = {
                'X-Frame-Options': 'Clickjacking protection',
                'X-XSS-Protection': 'XSS protection',
                'X-Content-Type-Options': 'MIME type sniffing protection',
                'Strict-Transport-Security': 'HTTPS enforcement',
                'Content-Security-Policy': 'Content security policy',
                'X-Powered-By': 'Technology disclosure (should be hidden)',
                'Server': 'Server disclosure'
            }
            
            for header, description in security_headers.items():
                if header in response.headers:
                    self.results['security_headers'][header] = {
                        'value': response.headers[header],
                        'description': description,
                        'present': True
                    }
                else:
                    self.results['security_headers'][header] = {
                        'value': None,
                        'description': description,
                        'present': False
                    }
                    
            # Add recommendations based on missing security headers
            missing_headers = [h for h, info in self.results['security_headers'].items() 
                             if not info['present'] and h not in ['X-Powered-By', 'Server']]
            
            if missing_headers:
                self.results['recommendations'].append(
                    f"Consider implementing missing security headers: {', '.join(missing_headers)}"
                )
                
        except Exception as e:
            print(f"[-] Header analysis failed: {str(e)}")

    def check_ssl_certificate(self):
        """Check SSL certificate information"""
        if self.parsed_url.scheme == 'https':
            try:
                print(f"[+] Checking SSL certificate...")
                context = ssl.create_default_context()
                
                with socket.create_connection((self.hostname, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        self.results['ssl_info'] = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter'],
                            'serial_number': cert['serialNumber']
                        }
                        
                        # Check certificate expiry
                        expiry_date = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (expiry_date - datetime.datetime.now()).days
                        
                        if days_until_expiry < 30:
                            self.results['recommendations'].append(
                                f"SSL certificate expires in {days_until_expiry} days - consider renewal"
                            )
                            
            except Exception as e:
                print(f"[-] SSL check failed: {str(e)}")

    def detect_technologies(self):
        """Detect web technologies using basic detection"""
        try:
            print(f"[+] Detecting technologies...")
            # Use basic technology detection only
            self._basic_tech_detection()
            
        except Exception as e:
            print(f"[-] Technology detection failed: {str(e)}")



    def _basic_tech_detection(self):
        """Basic technology detection from headers and content"""
        try:
            response = requests.get(self.target_url, timeout=10)
            
            # Check headers for technology indicators
            headers = response.headers
            
            if 'X-Powered-By' in headers:
                self.results['technologies']['X-Powered-By'] = headers['X-Powered-By']
                
            if 'Server' in headers:
                self.results['technologies']['Server'] = headers['Server']
                
            # Check for common CMS indicators in content
            content = response.text.lower()
            
            cms_indicators = {
                'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
                'joomla': ['joomla', '/components/', '/modules/'],
                'drupal': ['drupal', '/sites/default/', '/misc/drupal'],
                'apache': ['apache'],
                'nginx': ['nginx'],
                'iis': ['iis']
            }
            
            for tech, indicators in cms_indicators.items():
                for indicator in indicators:
                    if indicator in content:
                        self.results['technologies'][tech.title()] = "Detected in content"
                        break
                        
        except Exception as e:
            print(f"[-] Basic tech detection failed: {str(e)}")

    def generate_recommendations(self):
        """Generate security recommendations based on scan results"""
        recommendations = []
        
        # Check for insecure ports
        insecure_ports = [21, 23, 25, 110]  # FTP, Telnet, SMTP, POP3
        for port_info in self.results['open_ports']:
            if port_info['port'] in insecure_ports:
                recommendations.append(
                    f"Port {port_info['port']} ({port_info['service']}) is open and may be insecure"
                )
        
        # Check for HTTP instead of HTTPS
        if self.parsed_url.scheme == 'http':
            recommendations.append("Consider using HTTPS instead of HTTP for security")
        
        # Check for technology disclosure
        if 'X-Powered-By' in self.results['security_headers'] and \
           self.results['security_headers']['X-Powered-By']['present']:
            recommendations.append("Consider hiding X-Powered-By header to reduce information disclosure")
        
        self.results['recommendations'].extend(recommendations)

    def run_scan(self):
        """Run complete scan"""
        print(f"[+] Starting scan of {self.target_url}")
        print("="*50)
        
        self.resolve_hostname()
        self.port_scan()
        self.analyze_http_headers()
        self.check_ssl_certificate()
        self.detect_technologies()
        self.generate_recommendations()
        self.get_ai_recommendations()
        
        print("\n[+] Scan completed!")
        return self.results

    def _create_security_score_chart(self):
        """Create security score visualization"""
        fig, ax = plt.subplots(figsize=(6, 4))
        score = self.results['security_score']
        
        # Create gauge chart
        theta = np.linspace(0, np.pi, 100)
        r = 1
        
        # Background arc
        ax.plot(r * np.cos(theta), r * np.sin(theta), 'lightgray', linewidth=20)
        
        # Score arc
        score_theta = np.linspace(0, np.pi * (score/100), int(score))
        color = 'red' if score < 40 else 'orange' if score < 70 else 'green'
        ax.plot(r * np.cos(score_theta), r * np.sin(score_theta), color, linewidth=20)
        
        # Score text
        ax.text(0, -0.3, f'{score}/100', ha='center', va='center', fontsize=24, fontweight='bold')
        ax.text(0, -0.5, 'Security Score', ha='center', va='center', fontsize=12)
        
        ax.set_xlim(-1.2, 1.2)
        ax.set_ylim(-0.7, 1.2)
        ax.set_aspect('equal')
        ax.axis('off')
        plt.tight_layout()
        
        # Save to BytesIO
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()
        return img_buffer

    def _create_risk_distribution_chart(self):
        """Create risk distribution pie chart"""
        fig, ax = plt.subplots(figsize=(6, 4))
        
        # Calculate risk categories
        high_risk = len([p for p in self.results['open_ports'] if p['port'] in [21, 23, 25, 110]])
        medium_risk = len([p for p in self.results['open_ports'] if p['port'] in [22, 80]])
        low_risk = len(self.results['open_ports']) - high_risk - medium_risk
        missing_headers = len([h for h, i in self.results['security_headers'].items() if not i['present']])
        
        categories = ['High Risk Ports', 'Medium Risk Ports', 'Low Risk Ports', 'Missing Headers']
        values = [high_risk, medium_risk, low_risk, missing_headers]
        colors = ['#ff4444', '#ff8800', '#44ff44', '#ffaa00']
        
        # Filter out zero values
        filtered_data = [(cat, val, col) for cat, val, col in zip(categories, values, colors) if val > 0]
        if filtered_data:
            categories, values, colors = zip(*filtered_data)
            ax.pie(values, labels=categories, colors=colors, autopct='%1.0f', startangle=90)
        else:
            ax.text(0.5, 0.5, 'No Risk Issues Found', ha='center', va='center', transform=ax.transAxes)
        
        ax.set_title('Security Risk Distribution', fontsize=14, fontweight='bold')
        plt.tight_layout()
        
        img_buffer = BytesIO()
        plt.savefig(img_buffer, format='png', dpi=150, bbox_inches='tight')
        img_buffer.seek(0)
        plt.close()
        return img_buffer

    def generate_pdf_report(self, filename=None):
        """Generate PDF report"""
        if not filename:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"rlabs_security_report_{self.hostname}_{timestamp}.pdf"
        
        print(f"[+] Generating PDF report: {filename}")
        
        doc = SimpleDocTemplate(filename, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.darkblue
        )
        
        story.append(Paragraph("RLabs Security Web Scan Report", title_style))
        story.append(Spacer(1, 12))
        
        # Company Info
        company_style = ParagraphStyle(
            'CompanyInfo',
            parent=styles['Normal'],
            fontSize=10,
            alignment=TA_CENTER,
            textColor=colors.grey
        )
        
        story.append(Paragraph(f"{self.company_name} | {self.company_website}", company_style))
        story.append(Paragraph(f"Scan Type: {self.scan_type}", company_style))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        summary_text = f"""
        This report presents the results of a security assessment performed on {self.target_url}. 
        The scan identified {len(self.results['open_ports'])} open ports, analyzed security headers, 
        and detected {len(self.results['technologies'])} technologies. 
        Risk Level: <b>{self.results['risk_level']}</b> | Security Score: <b>{self.results['security_score']}/100</b>
        """
        story.append(Paragraph(summary_text, styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Security Score Visualization
        story.append(Paragraph("Security Score Analysis", styles['Heading2']))
        score_chart = self._create_security_score_chart()
        score_img = Image(score_chart, width=4*inch, height=2.5*inch)
        story.append(score_img)
        story.append(Spacer(1, 12))
        
        # Risk Distribution Chart
        story.append(Paragraph("Risk Distribution Analysis", styles['Heading2']))
        risk_chart = self._create_risk_distribution_chart()
        risk_img = Image(risk_chart, width=4*inch, height=2.5*inch)
        story.append(risk_img)
        story.append(Spacer(1, 12))
        
        # Scan Information
        story.append(Paragraph("Scan Information", styles['Heading2']))
        scan_data = [
            ['Target URL:', self.results['target']],
            ['Hostname:', self.results['hostname']],
            ['IP Address:', self.results['ip_address']],
            ['Scan Date:', self.results['scan_time']],
            ['Risk Level:', self.results['risk_level']],
            ['Security Score:', f"{self.results['security_score']}/100"]
        ]
        
        scan_table = Table(scan_data, colWidths=[2*inch, 4*inch])
        scan_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('BACKGROUND', (1, 0), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(scan_table)
        story.append(Spacer(1, 12))
        
        # Open Ports
        story.append(Paragraph("Open Ports", styles['Heading2']))
        if self.results['open_ports']:
            port_data = [['Port', 'Protocol', 'Service', 'State']]
            for port in self.results['open_ports']:
                port_data.append([
                    str(port['port']),
                    port['protocol'],
                    port['service'],
                    port['state']
                ])
            
            port_table = Table(port_data)
            port_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(port_table)
        else:
            story.append(Paragraph("No open ports detected in scan range.", styles['Normal']))
        
        story.append(Spacer(1, 12))
        
        # Security Headers
        story.append(Paragraph("Security Headers Analysis", styles['Heading2']))
        header_data = [['Header', 'Status', 'Value']]
        
        for header, info in self.results['security_headers'].items():
            status = "Present" if info['present'] else "Missing"
            value = info['value'] if info['value'] else "N/A"
            header_data.append([header, status, str(value)[:50] + "..." if len(str(value)) > 50 else str(value)])
        
        if len(header_data) > 1:
            header_table = Table(header_data, colWidths=[2.5*inch, 1*inch, 2.5*inch])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('FONTSIZE', (0, 1), (-1, -1), 8)
            ]))
            story.append(header_table)
        
        story.append(Spacer(1, 12))
        
        # Technologies
        story.append(Paragraph("Detected Technologies", styles['Heading2']))
        if self.results['technologies']:
            tech_text = ""
            for tech, version in self.results['technologies'].items():
                tech_text += f"• {tech}: {version}<br/>"
            story.append(Paragraph(tech_text, styles['Normal']))
        else:
            story.append(Paragraph("No specific technologies detected.", styles['Normal']))
        
        story.append(Spacer(1, 12))
        
        # SSL Information
        if self.results['ssl_info']:
            story.append(Paragraph("SSL Certificate Information", styles['Heading2']))
            ssl_text = f"""
            Subject: {self.results['ssl_info'].get('subject', {}).get('commonName', 'N/A')}<br/>
            Issuer: {self.results['ssl_info'].get('issuer', {}).get('organizationName', 'N/A')}<br/>
            Valid From: {self.results['ssl_info'].get('not_before', 'N/A')}<br/>
            Valid Until: {self.results['ssl_info'].get('not_after', 'N/A')}<br/>
            """
            story.append(Paragraph(ssl_text, styles['Normal']))
            story.append(Spacer(1, 12))
        
        # AI Recommendations
        if self.results['ai_recommendations']:
            story.append(Paragraph("AI-Powered Security Analysis", styles['Heading2']))
            ai_text = self.results['ai_recommendations'].replace('\n', '<br/>')
            story.append(Paragraph(ai_text, styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Basic Recommendations
        story.append(Paragraph("Basic Security Recommendations", styles['Heading2']))
        if self.results['recommendations']:
            rec_text = ""
            for i, rec in enumerate(self.results['recommendations'], 1):
                rec_text += f"{i}. {rec}<br/>"
            story.append(Paragraph(rec_text, styles['Normal']))
        else:
            story.append(Paragraph("No specific recommendations at this time.", styles['Normal']))
        
        # Disclaimer
        story.append(Spacer(1, 24))
        disclaimer = f"""
        <b>Disclaimer:</b> This report is generated by {self.company_name} automated scanning tool and should not be considered 
        a comprehensive security assessment. Professional security testing and manual review are recommended 
        for production systems. This scan was performed with non-intrusive methods only. 
        Visit {self.company_website} for professional security services.
        """
        story.append(Paragraph(disclaimer, styles['Normal']))
        
        doc.build(story)
        print(f"[+] PDF report saved as: {filename}")

def main():
    parser = argparse.ArgumentParser(description='RLabs Security Web Scanner - Professional Security Assessment')
    parser.add_argument('url', help='Target URL to scan (e.g., https://example.com)')
    parser.add_argument('-o', '--output', help='Output PDF filename')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.url.startswith(('http://', 'https://')):
        print("[-] Please provide a valid URL starting with http:// or https://")
        sys.exit(1)
    
    try:
        scanner = RLabsWebScanner(args.url)
        results = scanner.run_scan()
        scanner.generate_pdf_report(args.output)
        
        print("\n" + "="*50)
        print("SCAN SUMMARY")
        print("="*50)
        print(f"Target: {results['target']}")
        print(f"IP: {results['ip_address']}")
        print(f"Open Ports: {len(results['open_ports'])}")
        print(f"Technologies: {len(results['technologies'])}")
        print(f"Risk Level: {results['risk_level']}")
        print(f"Security Score: {results['security_score']}/100")
        print(f"Recommendations: {len(results['recommendations'])}")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()